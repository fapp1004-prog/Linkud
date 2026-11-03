// 시연 페이지 브라우저 확인 (Playwright). 시연 compose를 띄운 상태에서 실행한다.
//   node demo/browser_check.mjs [http://127.0.0.1:8080] [스크린샷 폴더]
// 확인하는 것:
//   1. 장면별로 실제 값이 그려진다(장면 3의 참조 번호 형식, 감사 기록) → 스크린샷 저장
//   2. 오염 문장(HTML·스크립트)을 넣어도 실행되지 않고 글자로만 보인다(이스케이프)
//   3. 실시간 연결이 끊기면 '연결 끊김'을 표시하고, 재현 화면은 그대로 진행된다
//   4. CSP가 인라인 스크립트를 막는다
// playwright는 전역 설치(NODE_PATH=$(npm root -g))나 로컬 설치 모두에서 찾도록 require로 불러온다
import { createRequire } from "node:module";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

const { chromium } = createRequire(import.meta.url)("playwright");

const BASE = process.argv[2] || "http://127.0.0.1:8080";
const SHOTS = process.argv[3] || "";
const results = [];
const check = (name, ok, extra = "") => {
  results.push(ok);
  console.log(`${ok ? "통과" : "실패"}: ${name}${extra ? " (" + extra + ")" : ""}`);
};

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1600, height: 900 }, deviceScaleFactor: 1 });

async function gotoScene(page, n) {
  await page.goto(BASE, { waitUntil: "networkidle" });
  for (let i = 0; i < n; i++) await page.keyboard.press("ArrowRight");
}

// 1. 장면별 실제 값 + 스크린샷
{
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  const res = await page.goto(BASE, { waitUntil: "networkidle" });
  const csp = res.headers()["content-security-policy"] || "";
  check("CSP 헤더(script-src 'self')", csp.includes("script-src 'self'") && !csp.includes("unsafe-inline"));
  if (SHOTS) mkdirSync(SHOTS, { recursive: true });
  const names = ["0-cover", "1-without-linkud", "2-tool-manual", "3-with-linkud", "4-how", "5-rugpull"];
  for (let i = 0; i < names.length; i++) {
    if (i > 0) await page.keyboard.press("ArrowRight");
    await page.waitForTimeout(3200); // 연출 채팅이 다 나오고 실시간 값이 올 때까지
    if (i === 2) {
      // 형광펜은 문장 경계까지: 단어 중간에서 시작하거나 끝나지 않는다
      const marks = await page.locator(".manual mark").allTextContents();
      const ok = marks.length > 0 && marks.every((m) => /^[A-Z가-힣]/.test(m) && /[.!?]$/.test(m));
      check("장면 2 형광펜이 문장 단위", ok, marks.join(" | "));
    }
    if (i === 3) {
      const ref = await page.locator(".kv-ref .kv-value").textContent({ timeout: 15000 });
      check("장면 3 참조 번호", /^LK-[0-9A-HJKMNP-TV-Z]{8}$/.test(ref || ""), ref);
      const audit = await page.locator(".audit").textContent({ timeout: 15000 });
      check("장면 3 감사 기록 조회", (audit || "").includes("translator"));
    }
    if (i === 5) {
      await page.locator("button.action").click();
      await page.locator(".rug-off").waitFor({ timeout: 15000 });
      check("장면 5 러그풀 뒤 사라짐", true);
      await page.waitForTimeout(500);
    }
    if (SHOTS) await page.screenshot({ path: join(SHOTS, `${names[i]}.png`) });
  }
  check("페이지 스크립트 오류 없음", errors.length === 0, errors.join("; "));
  await page.close();
}

// 2. 오염 문장 이스케이프: 드라이버 응답을 가로채 HTML·스크립트를 넣어 본다
{
  const page = await ctx.newPage();
  const evil = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script><b>굵게</b>';
  await page.route("**/driver/raw-tool", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        server: "<i>s</i>",
        name: "<svg onload=window.__pwned=3>",
        description: evil,
        highlights: [{ start: 0, end: 20 }],
      }),
    })
  );
  await page.route("**/driver/scene/3", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ visible: ["<img src=x onerror=window.__pwned=4>"], message: evil, ref: null }),
    })
  );
  await gotoScene(page, 2);
  await page.waitForTimeout(1500);
  const shown = await page.locator(".manual").textContent();
  check("오염 HTML이 글자로만 보임", (shown || "") === evil);
  await page.keyboard.press("ArrowRight");
  await page.waitForTimeout(1500);
  const deny = await page.locator(".deny").textContent();
  check("거부 문구 자리에 넣은 HTML도 글자로만", (deny || "") === evil);
  const injected = await page.evaluate(() => document.querySelectorAll(".manual img, .manual script, .manual b, .deny img, .tools img").length);
  check("주입한 요소가 DOM에 생기지 않음", injected === 0);
  const pwned = await page.evaluate(() => window.__pwned);
  check("주입한 스크립트 실행 안 됨", pwned === undefined, String(pwned));
  // CSP: 인라인 스크립트를 직접 붙여도 실행되지 않는다
  await page.evaluate(() => {
    const s = document.createElement("script");
    s.textContent = "window.__inline = 1";
    document.body.appendChild(s);
  });
  check("CSP가 인라인 스크립트 차단", (await page.evaluate(() => window.__inline)) === undefined);
  await page.close();
}

// 3. 연결 끊김: 실시간 경로를 모두 끊어도 재현 화면은 진행된다
{
  const page = await ctx.newPage();
  await page.route("**/driver/**", (route) => route.abort());
  await page.route("**/api/**", (route) => route.abort());
  await gotoScene(page, 3);
  await page.waitForTimeout(3200);
  const live = await page.locator("#live").textContent();
  check("실시간 패널에 '연결 끊김'", (live || "").includes("연결 끊김"));
  check("실시간 패널에 지어낸 참조 번호 없음", !/LK-[0-9A-Z]{8}/.test(live || ""));
  const staged = await page.locator("#staged .bubble").count();
  check("재현 화면은 그대로 진행", staged >= 2, String(staged));
  const conn = await page.locator("#conn").textContent();
  check("상단 연결 표시도 끊김", (conn || "").includes("연결 끊김"));
  if (SHOTS) await page.screenshot({ path: join(SHOTS, "x-disconnected.png") });
  await page.close();
}

await browser.close();
process.exit(results.every(Boolean) ? 0 : 1);
