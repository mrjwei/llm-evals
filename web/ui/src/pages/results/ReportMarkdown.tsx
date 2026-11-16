// A run's report.md as React elements (decision 020): react-markdown builds
// elements, never HTML strings, and `skipHtml` drops any raw HTML in the
// file. Links to another report.md of the same run open in the page;
// charts load from the run's files route; anything else that points
// outside the run is shown as text.
import Markdown, { type Components } from "react-markdown";
import { Link } from "react-router";
import remarkGfm from "remark-gfm";
import { fileUrl, isExternal, resolveInRun } from "@/lib/results";
import { query } from "@/lib/api";

export function ReportMarkdown({ address, doc, markdown }: { address: string; doc: string; markdown: string }) {
  const components: Components = {
    h1: ({ children }) => <h1 className="mt-2 mb-3 text-2xl font-semibold tracking-tight">{children}</h1>,
    h2: ({ children }) => <h2 className="mt-8 mb-3 border-b pb-1 text-lg font-semibold">{children}</h2>,
    h3: ({ children }) => <h3 className="mt-6 mb-2 text-base font-semibold">{children}</h3>,
    p: ({ children }) => <p className="my-3 text-sm leading-relaxed">{children}</p>,
    blockquote: ({ children }) => <blockquote className="my-3 border-l-4 pl-4 text-muted-foreground italic">{children}</blockquote>,
    ul: ({ children }) => <ul className="my-3 list-disc space-y-1 pl-6 text-sm">{children}</ul>,
    ol: ({ children }) => <ol className="my-3 list-decimal space-y-1 pl-6 text-sm">{children}</ol>,
    code: ({ children }) => <code className="rounded bg-muted px-1 py-0.5 font-mono text-[0.8em]">{children}</code>,
    pre: ({ children }) => <pre className="my-3 overflow-x-auto rounded-md bg-muted/50 p-3 text-xs">{children}</pre>,
    table: ({ children }) => (
      <div className="my-4 overflow-x-auto rounded-md border">
        <table className="w-full border-collapse text-sm">{children}</table>
      </div>
    ),
    thead: ({ children }) => <thead className="bg-muted/50">{children}</thead>,
    th: ({ children, style }) => <th style={style} className="border-b px-3 py-2 text-left font-medium whitespace-nowrap">{children}</th>,
    td: ({ children, style }) => <td style={style} className="border-b px-3 py-1.5 align-top tabular-nums">{children}</td>,
    hr: () => <hr className="my-6" />,
    a: ({ href, children }) => {
      if (href && isExternal(href)) {
        return (
          <a href={href} target="_blank" rel="noreferrer noopener" className="underline underline-offset-4">
            {children}
          </a>
        );
      }
      const target = href ? resolveInRun(doc, href) : null;
      if (target && target.endsWith("report.md")) {
        return (
          <Link to={{ search: query({ doc: target === "report.md" ? null : target }) }} className="font-medium underline underline-offset-4">
            {children}
          </Link>
        );
      }
      return <span>{children}</span>;
    },
    img: ({ src, alt }) => {
      const target = typeof src === "string" ? resolveInRun(doc, src) : null;
      if (!target || !target.endsWith(".png")) return <span className="text-muted-foreground">[{alt ?? "image"}]</span>;
      return <img src={fileUrl(address, target)} alt={alt ?? ""} loading="lazy" className="my-4 w-full max-w-3xl rounded-md border bg-white" />;
    },
  };
  return (
    <div className="min-w-0">
      <Markdown remarkPlugins={[remarkGfm]} skipHtml components={components}>
        {markdown}
      </Markdown>
    </div>
  );
}
