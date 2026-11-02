//! The small Markdown subset posts are written in, parsed into blocks that each client renders
//! its own way. Posts are never HTML: anything that isn't markup is text.
//!
//! Blocks, one per run of lines:
//! - paragraphs, separated by blank lines; single line breaks are kept
//! - quotes: lines starting with `>` (but not `>>12`, which links to a post)
//! - lists: lines starting with `- ` or `* `
//! - code: lines between two fences of three backticks
//!
//! Within a line: `` `code` ``, `**strong**`, `*emphasis*`, `>>12` (a link to post 12 on the
//! same board), and `http://` or `https://` addresses. A backslash before a markup character
//! keeps it as text.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Block {
    Paragraph(Vec<Inline>),
    Quote(Vec<Inline>),
    List(Vec<Vec<Inline>>),
    Code(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inline {
    Text(String),
    Code(String),
    Strong(String),
    Emphasis(String),
    /// A post on the same board, by number
    PostRef(u64),
    Link(String),
    LineBreak,
}

const FENCE: &str = "```";

/// A post's body as blocks
pub fn parse(body: &str) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut lines = body.lines().peekable();
    while let Some(line) = lines.next() {
        if line.trim().is_empty() {
            continue;
        }
        if line.trim_start().starts_with(FENCE) {
            let mut code = Vec::new();
            for line in lines.by_ref() {
                if line.trim_start().starts_with(FENCE) {
                    break;
                }
                code.push(line);
            }
            blocks.push(Block::Code(code.join("\n")));
            continue;
        }
        let kind = kind(line);
        let mut run = vec![line];
        while let Some(next) = lines.peek() {
            if next.trim().is_empty() || next.trim_start().starts_with(FENCE) || self::kind(next) != kind {
                break;
            }
            run.push(lines.next().expect("peeked"));
        }
        blocks.push(match kind {
            Kind::Paragraph => Block::Paragraph(joined(run.iter().map(|line| line.trim()))),
            Kind::Quote => Block::Quote(joined(run.iter().map(|line| line.trim_start()[1..].trim()))),
            Kind::List => Block::List(run.iter().map(|line| inlines(line.trim_start()[2..].trim())).collect()),
        });
    }
    blocks
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Paragraph,
    Quote,
    List,
}

fn kind(line: &str) -> Kind {
    let line = line.trim_start();
    if line.starts_with('>') && post_ref(line).is_none() {
        Kind::Quote
    } else if line.starts_with("- ") || line.starts_with("* ") {
        Kind::List
    } else {
        Kind::Paragraph
    }
}

/// Lines as one run of inlines, with their breaks
fn joined<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<Inline> {
    let mut out = Vec::new();
    for (i, line) in lines.enumerate() {
        if i > 0 {
            out.push(Inline::LineBreak);
        }
        out.extend(inlines(line));
    }
    out
}

/// `>>12` at the start of `text`: the number and the length of the reference
fn post_ref(text: &str) -> Option<(u64, usize)> {
    let digits = text.strip_prefix(">>")?;
    let len = digits.bytes().take_while(u8::is_ascii_digit).count();
    let number = digits[..len].parse().ok()?;
    // `>>12abc` isn't a reference
    let after = digits[len..].chars().next();
    if after.is_some_and(char::is_alphanumeric) {
        return None;
    }
    Some((number, 2 + len))
}

/// An address at the start of `text`, without trailing punctuation
fn link(text: &str) -> Option<usize> {
    if !(text.starts_with("http://") || text.starts_with("https://")) {
        return None;
    }
    let mut end = text.find(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '"' | '`')).unwrap_or(text.len());
    while text[..end].ends_with(['.', ',', ';', ':', '!', '?', ')', '\'', '*']) {
        end -= 1;
    }
    (text[..end].len() > text.find("//")? + 2).then_some(end)
}

/// Text enclosed by `marker` at the start of `text`: the inside and the whole length
fn enclosed<'a>(text: &'a str, marker: &str) -> Option<(&'a str, usize)> {
    let rest = text.strip_prefix(marker)?;
    let end = rest.find(marker)?;
    let inside = &rest[..end];
    let tight = !inside.is_empty() && !inside.starts_with(char::is_whitespace) && !inside.ends_with(char::is_whitespace);
    tight.then_some((inside, marker.len() * 2 + end))
}

/// The markup at the start of `text`, and its length
fn markup_at(text: &str, word_start: bool) -> Option<(Inline, usize)> {
    let owned = |(inside, len): (&str, usize)| (inside.to_string(), len);
    if text.starts_with('`') {
        enclosed(text, "`").map(owned).map(|(s, len)| (Inline::Code(s), len))
    } else if text.starts_with("**") {
        enclosed(text, "**").map(owned).map(|(s, len)| (Inline::Strong(s), len))
    } else if text.starts_with('*') {
        enclosed(text, "*").map(owned).map(|(s, len)| (Inline::Emphasis(s), len))
    } else if !word_start {
        None
    } else if let Some((number, len)) = post_ref(text) {
        Some((Inline::PostRef(number), len))
    } else {
        link(text).map(|len| (Inline::Link(text[..len].to_string()), len))
    }
}

fn inlines(line: &str) -> Vec<Inline> {
    let mut out = Vec::new();
    let mut text = String::new();
    let mut rest = line;
    // Links and post references start only at the start of a word
    let mut word_start = true;
    while let Some(c) = rest.chars().next() {
        if c == '\\' && rest[1..].starts_with(['\\', '`', '*', '>']) {
            text.push_str(&rest[1..2]);
            rest = &rest[2..];
            word_start = false;
            continue;
        }
        match markup_at(rest, word_start) {
            Some((inline, len)) => {
                if !text.is_empty() {
                    out.push(Inline::Text(std::mem::take(&mut text)));
                }
                out.push(inline);
                rest = &rest[len..];
                word_start = false;
            }
            None => {
                text.push(c);
                rest = &rest[c.len_utf8()..];
                word_start = c.is_whitespace() || matches!(c, '(' | '[');
            }
        }
    }
    if !text.is_empty() {
        out.push(Inline::Text(text));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use Inline::*;

    fn text(s: &str) -> Inline {
        Text(s.to_string())
    }

    #[test]
    fn blocks() {
        let body = "First line\nsecond line\n\n> quoted\n>also\n\n- one\n* two\n\n```\n<b>code</b>\n\n**not strong**\n```\nafter";
        assert_eq!(
            parse(body),
            vec![
                Block::Paragraph(vec![text("First line"), LineBreak, text("second line")]),
                Block::Quote(vec![text("quoted"), LineBreak, text("also")]),
                Block::List(vec![vec![text("one")], vec![text("two")]]),
                Block::Code("<b>code</b>\n\n**not strong**".into()),
                Block::Paragraph(vec![text("after")]),
            ]
        );
    }

    #[test]
    fn a_post_reference_at_the_start_of_a_line_isnt_a_quote() {
        assert_eq!(parse(">>12 agreed"), vec![Block::Paragraph(vec![PostRef(12), text(" agreed")])]);
        assert_eq!(parse(">>> deep"), vec![Block::Quote(vec![text(">> deep")])]);
    }

    #[test]
    fn inline_markup() {
        assert_eq!(
            inlines("a `x*y` **bold** *em* (see >>3) https://example.i2p/a?b=1. done"),
            vec![
                text("a "),
                Code("x*y".into()),
                text(" "),
                Strong("bold".into()),
                text(" "),
                Emphasis("em".into()),
                text(" (see "),
                PostRef(3),
                text(") "),
                Link("https://example.i2p/a?b=1".into()),
                text(". done"),
            ]
        );
    }

    #[test]
    fn things_that_look_like_markup_but_arent() {
        assert_eq!(inlines("2 * 3 * 4"), vec![text("2 * 3 * 4")]);
        assert_eq!(inlines("a>>3 >>3x http:// <b>"), vec![text("a>>3 >>3x http:// <b>")]);
        assert_eq!(inlines(r"\*not em\* \>>4"), vec![text("*not em* >>4")]);
        assert_eq!(inlines("unclosed `code and **strong"), vec![text("unclosed `code and **strong")]);
        assert_eq!(inlines("ünïcödé *ok*"), vec![text("ünïcödé "), Emphasis("ok".into())]);
    }

    #[test]
    fn an_unclosed_fence_runs_to_the_end() {
        assert_eq!(parse("```\ncode\nmore"), vec![Block::Code("code\nmore".into())]);
    }
}
