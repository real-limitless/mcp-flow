import { describe, expect, it } from "vitest";
import { escapeHtml, markdownToHtml } from "../scripts/site/md.js";

describe("site markdown", () => {
  it("escapes html", () => {
    expect(escapeHtml('<a href="x">')).toBe("&lt;a href=&quot;x&quot;&gt;");
  });

  it("renders basic markdown", () => {
    const html = markdownToHtml("# Title\n\nHello **bold** and `code`\n\n- a\n- b\n");
    expect(html).toContain("<h1>Title</h1>");
    expect(html).toContain("<strong>bold</strong>");
    expect(html).toContain("<code>code</code>");
    expect(html).toContain("<li>a</li>");
  });

  it("renders fenced code safely", () => {
    const html = markdownToHtml("```\n<script>x</script>\n```");
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain("<script>x</script>");
  });
});
