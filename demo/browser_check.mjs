// 시연 페이지 브라우저 확인 (Playwright). 시연 compose를 띄운 상태에서 실행한다.
//   node demo/browser_check.mjs [http://127.0.0.1:8080] [스크린샷 폴더]
// 확인하는 것:
//   1. → 로 한 단계씩 진행, 장면별 실제 값(장면 3 참조 번호, 연결된 도구 변화, 러그풀) → 스크린샷
//   2. ← 로 되돌리기, N 키 발표자 메모, 1920×1080·1366×768에서 앱 창이 잘리지 않음
//   3. 오염 문장(HTML·스크립트)을 넣어도 실행되지 않고 글자로만 보인다(이스케이프)
//   4. 실제 값 연결이 끊기면 그 자리에 '연결 끊김'을 표시하고, 채팅 연출은 그대로 진행된다
//   5. CSP가 인라인 스크립트를 막는다
// playwright는 전역 설치(NODE_PATH=$(npm root -g))나 로컬 설치 모두에서 찾도록 require로 불러온다
import { createRequire } from "node:module";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

const { chromium } = createRequire(import.meta.url)("playwright");

const BASE = process.argv[2] || "http://127.0.0.1:8080";
const SHOTS = process.argv[3] || "";
const REF = /LK-[0-9A-HJKMNP-TV-Z]{8}/;
// 단계 번호 (demo/web/app.js의 steps 순서)
const STEP = { s1Done: 6, s2Open: 10, s2Done: 12, s3Done: 18, s3Card: 17, s4Done: 20, finale: 21 };
const results = [];
const check = (name, ok, extra = "") => {
  results.push(ok);
  console.log(`${ok ? "통과" : "실패"}: ${name}${extra ? " (" + extra + ")" : ""}`);
};

const browser = await chromium.launch();

async function idle(page) {
  await page.waitForFunction(() => document.body.dataset.busy === "0", null, { timeout: 30000 });
}
async function forward(page, times) {
  for (let i = 0; i < times; i++) {
    await page.keyboard.press("ArrowRight");
    await idle(page);
  }
}
async function open(ctx) {
  const page = await ctx.newPage();
  const res = await page.goto(BASE, { waitUntil: "networkidle" });
  await idle(page);
  return { page, res };
}
const liveChips = (page) =>
  page.$$eval("#tools .chip:not(.chip-gone)", (els) => els.map((e) => e.textContent));

// 1·2. 실제 값으로 끝까지 진행 + 스크린샷 (1920×1080)
{
  const ctx = await browser.newContext({ viewport: { width: 1920, height: 1080 } });
  const { page, res } = await open(ctx);
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  const csp = res.headers()["content-security-policy"] || "";
  check("CSP 헤더(script-src 'self')", csp.includes("script-src 'self'") && !csp.includes("unsafe-inline"));
  check("탭 제목", (await page.title()) === "AI 비서를 지키는 문지기");
  if (SHOTS) mkdirSync(SHOTS, { recursive: true });
  const shot = async (name) => {
    if (!SHOTS) return;
    await page.waitForTimeout(900); // 부드러운 스크롤이 끝날 때까지
    await page.screenshot({ path: join(SHOTS, `${name}.png`) });
  };

  await shot("0-cover");
  await forward(page, STEP.s1Done);
  check("장면 1 가짜 키 표시", (await page.locator(".row-warn .row-value").textContent()).includes("시연용 가짜 비밀키"));
  await shot("1-without-guard");

  await forward(page, STEP.s2Done - STEP.s1Done);
  const marks = await page.locator(".manual mark").allTextContents();
  check(
    "장면 2 형광펜이 문장 단위",
    marks.length > 0 && marks.every((m) => /^[A-Z가-힣]/.test(m) && /[.!?]$/.test(m)),
    marks.join(" | ")
  );
  await shot("2-why");

  await forward(page, STEP.s3Done - STEP.s2Done);
  await page.waitForTimeout(1600); // 사라지는 칩 연출이 끝날 때까지
  const ref = await page.locator(".card-blocked .row-ref .row-value").textContent();
  check("장면 3 실제 참조 번호", REF.test(ref || ""), ref);
  check("장면 3 '실제 Linkud 응답' 표시", (await page.locator(".card-blocked .real-tag").textContent()) === "실제 Linkud 응답");
  const chips3 = await liveChips(page);
  check("장면 3 연결된 도구에서 번역이 사라짐", !chips3.includes("번역") && chips3.includes("메모"), chips3.join(","));
  await shot("3-with-guard");

  // ← 되돌리기: 메시지가 줄고, 다시 → 하면 같은 참조 번호(새로 만들지 않음)
  const before = await page.locator("#chat .msg").count();
  await page.keyboard.press("ArrowLeft");
  await idle(page);
  const after = await page.locator("#chat .msg").count();
  check("← 로 한 단계 되돌리기", after === before - 1, `${before} → ${after}`);
  await forward(page, 1);
  check("다시 → 해도 같은 참조 번호", (await page.locator(".card-blocked .row-ref .row-value").textContent()) === ref);

  // 화면 잘림 없음
  const fits = await page.evaluate(() => {
    const app = document.querySelector(".app").getBoundingClientRect();
    const composer = document.querySelector(".composer").getBoundingClientRect();
    const cards = Array.from(document.querySelectorAll(".card")).every((c) => c.getBoundingClientRect().right <= app.right + 1);
    return app.bottom <= innerHeight && composer.bottom <= innerHeight && document.documentElement.scrollWidth <= innerWidth && cards;
  });
  check("1920×1080 잘림 없음", fits);

  // N 키 발표자 메모
  check("발표자 메모 기본 숨김", await page.locator("#notes").isHidden());
  await page.keyboard.press("n");
  check("N 키로 발표자 메모 켜짐", (await page.locator("#notes").isVisible()) && (await page.locator("#notes-body").textContent()).length > 10);
  await shot("n-notes");
  await page.keyboard.press("n");
  check("N 키로 다시 숨김", await page.locator("#notes").isHidden());

  await forward(page, STEP.s4Done - STEP.s3Done);
  await page.waitForTimeout(1600);
  const chips4 = await liveChips(page);
  check("장면 4 바뀐 요약 도구가 사라짐", !chips4.includes("요약"), chips4.join(","));
  await shot("4-rugpull");

  await forward(page, STEP.finale - STEP.s4Done);
  await page.waitForTimeout(500);
  const stats = await page.locator(".stat-big").allTextContents();
  check("마무리 숫자(평가 결과에서 읽음)", stats.length >= 2 && /\d+개 중 \d+개/.test(stats[0]), stats.join(" | "));
  await shot("5-numbers");

  check("구석 '재현 화면' 표시", (await page.locator("#staged-badge").textContent()).includes("재현 화면"));
  check("페이지 스크립트 오류 없음", errors.length === 0, errors.join("; "));
  await ctx.close();
}

// 2. 1366×768에서도 잘림 없음
{
  const ctx = await browser.newContext({ viewport: { width: 1366, height: 768 } });
  const { page } = await open(ctx);
  await forward(page, STEP.s3Done);
  const fits = await page.evaluate(() => {
    const app = document.querySelector(".app").getBoundingClientRect();
    const composer = document.querySelector(".composer").getBoundingClientRect();
    const head = document.querySelector(".app-head").getBoundingClientRect();
    return app.bottom <= innerHeight && composer.bottom <= innerHeight && head.top >= 0 && document.documentElement.scrollWidth <= innerWidth;
  });
  check("1366×768 잘림 없음", fits);
  if (SHOTS) await page.screenshot({ path: join(SHOTS, "x-1366x768.png") });
  await ctx.close();
}

// 3. 오염 문장 이스케이프: 드라이버 응답을 가로채 HTML·스크립트를 넣어 본다
{
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 900 } });
  const page = await ctx.newPage();
  const evil = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script><b>굵게</b>';
  await page.route("**/driver/raw-tool", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ name: "<svg onload=window.__pwned=3>", description: evil, highlights: [{ start: 0, end: 20 }] }),
    })
  );
  await page.route("**/driver/scene/3", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ visible: ["<img src=x onerror=window.__pwned=4>"], message: evil, ref: null }),
    })
  );
  await page.goto(BASE, { waitUntil: "networkidle" });
  await idle(page);
  await forward(page, STEP.s2Open);
  check("오염 HTML이 글자로만 보임", (await page.locator(".manual").first().textContent()) === evil);
  await forward(page, STEP.s3Card + 1 - STEP.s2Open);
  check("거부 문구 자리에 넣은 HTML도 글자로만", (await page.locator(".deny").textContent()) === evil);
  const injected = await page.evaluate(() => document.querySelectorAll("#chat img, #chat script, #chat b, #chat svg, #tools img").length);
  check("주입한 요소가 DOM에 생기지 않음", injected === 0);
  check("주입한 스크립트 실행 안 됨", (await page.evaluate(() => window.__pwned)) === undefined);
  await page.evaluate(() => {
    const s = document.createElement("script");
    s.textContent = "window.__inline = 1";
    document.body.appendChild(s);
  });
  check("CSP가 인라인 스크립트 차단", (await page.evaluate(() => window.__inline)) === undefined);
  await ctx.close();
}

// 4. 연결 끊김: 실제 값 경로를 모두 끊어도 채팅 연출은 진행된다
{
  const ctx = await browser.newContext({ viewport: { width: 1920, height: 1080 } });
  const page = await ctx.newPage();
  await page.route("**/driver/**", (route) => route.abort());
  await page.route("**/api/**", (route) => route.abort());
  await page.goto(BASE, { waitUntil: "networkidle" });
  await idle(page);
  await forward(page, STEP.s3Done);
  const lost = await page.locator(".lost").count();
  check("실제 값 자리에 '연결 끊김'", lost >= 2, String(lost));
  check("연결된 도구 자리도 '연결 끊김'", (await liveChips(page)).includes("연결 끊김"));
  const text = await page.locator("#chat").textContent();
  check("지어낸 참조 번호 없음", !REF.test(text || ""));
  check("채팅 연출은 그대로 진행", (await page.locator("#chat .msg-user").count()) >= 3);
  if (SHOTS) await page.screenshot({ path: join(SHOTS, "x-disconnected.png") });
  await ctx.close();
}

await browser.close();
process.exit(results.every(Boolean) ? 0 : 1);
