/** Minimal safe Markdown → HTML (no deps). Good enough for README excerpts. */

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function markdownToHtml(md: string, maxChars = 48_000): string {
  let src = md.replace(/\r\n/g, "\n");
  if (src.length > maxChars) {
    src = `${src.slice(0, maxChars)}\n\n… *(truncated)*`;
  }

  const blocks: string[] = [];
  // fenced code
  src = src.replace(/```[\w.-]*\n([\s\S]*?)```/g, (_m, code: string) => {
    const i = blocks.length;
    blocks.push(`<pre><code>${escapeHtml(code.replace(/\n$/, ""))}</code></pre>`);
    return `\u0000B${i}\u0000`;
  });

  const lines = src.split("\n");
  const out: string[] = [];
  let i = 0;
  let inUl = false;
  let inOl = false;
  let inBq = false;

  const closeLists = () => {
    if (inUl) {
      out.push("</ul>");
      inUl = false;
    }
    if (inOl) {
      out.push("</ol>");
      inOl = false;
    }
    if (inBq) {
      out.push("</blockquote>");
      inBq = false;
    }
  };

  while (i < lines.length) {
    const line = lines[i]!;

    if (line.startsWith("\u0000B")) {
      closeLists();
      const m = line.match(/\u0000B(\d+)\u0000/);
      if (m) out.push(blocks[Number(m[1])]!);
      i++;
      continue;
    }

    if (/^\s*$/.test(line)) {
      closeLists();
      i++;
      continue;
    }

    const hm = line.match(/^(#{1,4})\s+(.*)$/);
    if (hm) {
      closeLists();
      const level = hm[1]!.length;
      out.push(`<h${level}>${inline(hm[2]!)}</h${level}>`);
      i++;
      continue;
    }

    if (/^---+$/.test(line.trim()) || /^\*\*\*+$/.test(line.trim())) {
      closeLists();
      out.push("<hr />");
      i++;
      continue;
    }

    if (/^>\s?/.test(line)) {
      if (!inBq) {
        closeLists();
        out.push("<blockquote>");
        inBq = true;
      }
      out.push(`<p>${inline(line.replace(/^>\s?/, ""))}</p>`);
      i++;
      continue;
    }

    if (/^[-*+]\s+/.test(line)) {
      if (!inUl) {
        closeLists();
        out.push("<ul>");
        inUl = true;
      }
      out.push(`<li>${inline(line.replace(/^[-*+]\s+/, ""))}</li>`);
      i++;
      continue;
    }

    if (/^\d+\.\s+/.test(line)) {
      if (!inOl) {
        closeLists();
        out.push("<ol>");
        inOl = true;
      }
      out.push(`<li>${inline(line.replace(/^\d+\.\s+/, ""))}</li>`);
      i++;
      continue;
    }

    closeLists();
    // paragraph: gather until blank
    const para = [line];
    i++;
    while (i < lines.length && lines[i] && !/^\s*$/.test(lines[i]!) && !/^#{1,4}\s/.test(lines[i]!) && !/^[-*+]\s/.test(lines[i]!) && !/^>\s?/.test(lines[i]!) && !/^```/.test(lines[i]!) && !lines[i]!.startsWith("\u0000B")) {
      para.push(lines[i]!);
      i++;
    }
    out.push(`<p>${inline(para.join(" "))}</p>`);
  }
  closeLists();
  return out.join("\n");
}

function inline(s: string): string {
  let t = escapeHtml(s);
  t = t.replace(/`([^`]+)`/g, "<code>$1</code>");
  t = t.replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2" rel="noopener noreferrer">$1</a>');
  t = t.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  t = t.replace(/(?<![\w*])\*([^*]+)\*(?![\w*])/g, "<em>$1</em>");
  return t;
}
