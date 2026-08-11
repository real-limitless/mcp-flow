(function () {
  const q = document.getElementById("q");
  const grid = document.getElementById("grid");
  const empty = document.getElementById("empty");
  if (q && grid) {
    const cards = Array.from(grid.querySelectorAll(".card"));
    const run = () => {
      const term = (q.value || "").trim().toLowerCase();
      let n = 0;
      for (const c of cards) {
        const hay = [
          c.getAttribute("data-id") || "",
          c.getAttribute("data-title") || "",
          c.getAttribute("data-summary") || "",
          c.getAttribute("data-transport") || "",
        ]
          .join(" ")
          .toLowerCase();
        const show = !term || hay.includes(term);
        c.classList.toggle("hidden", !show);
        if (show) n++;
      }
      if (empty) empty.classList.toggle("hidden", n > 0 || !term);
    };
    q.addEventListener("input", run);
  }

  document.querySelectorAll("[data-copy-target]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-copy-target");
      const el = id ? document.getElementById(id) : null;
      const text = el ? el.innerText : "";
      try {
        await navigator.clipboard.writeText(text);
        const prev = btn.textContent;
        btn.textContent = "Copied";
        setTimeout(() => {
          btn.textContent = prev;
        }, 1200);
      } catch {
        btn.textContent = "Copy failed";
      }
    });
  });
})();
