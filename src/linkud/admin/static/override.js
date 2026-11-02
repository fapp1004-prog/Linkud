// Linkud 임시 허용 페이지. 서버 응답은 textContent로만 넣고, 토큰은 이 함수 안의 변수로만 쓴 뒤 버린다
// (브라우저 저장소·쿠키에 저장하지 않음). CSP가 인라인 스크립트를 막으므로 이 파일로만 동작한다.
"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("override-form");
  const result = document.getElementById("result");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const tokenInput = document.getElementById("token");
    const token = tokenInput.value;
    tokenInput.value = "";
    result.textContent = "요청 중…";
    let message;
    try {
      const response = await fetch("/override", {
        method: "POST",
        credentials: "omit",
        cache: "no-store",
        headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },
        body: JSON.stringify({
          ref: document.getElementById("ref").value.trim(),
          reason: document.getElementById("reason").value,
        }),
      });
      const data = await response.json().catch(() => ({}));
      if (response.ok && data.granted) {
        message = "허용됨: " + String(data.tool) + " (만료 " + String(data.expires_at) + ")";
      } else if (response.status === 401) {
        message = "토큰이 맞지 않습니다.";
      } else {
        message = String(data.error || "요청을 처리하지 못했습니다.");
      }
    } catch (err) {
      message = "요청을 보내지 못했습니다.";
    }
    result.textContent = message;
  });
});
