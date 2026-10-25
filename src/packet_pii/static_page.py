"""Lossy, inert structure/text projection of already-authorised captured HTML.

This is not an HTML sanitizer or browser engine: a fresh allowlisted tree is
built, without any captured attributes, CSS, URLs, resources or active content.
Consumers must create elements/text nodes, never inject the original source.
"""
from collections import Counter
from html import escape
from html.parser import HTMLParser

MAX_INPUT_BYTES = 64 * 1024
MAX_NODES = 4096
MAX_DEPTH = 64
TAGS = frozenset(('p div section article header footer main aside blockquote '
    'h1 h2 h3 h4 h5 h6 ul ol li pre code em strong b i u s br hr table thead '
    'tbody tfoot tr th td caption dl dt dd span address figure figcaption').split())
VOID = frozenset(('br', 'hr'))
DROP = frozenset(('head script style template noscript iframe object embed svg '
    'math textarea select button video audio canvas').split())
HTML_VOID = frozenset(('area base br col embed hr img input link meta param source track wbr').split())


class _Projection(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = []
        self.stack = []
        self.suppressed = []
        self.omitted = Counter()
        self.attributes = 0
        self.nodes = 0
        self.truncated = False

    def append(self, item):
        if self.nodes >= MAX_NODES:
            self.truncated = True
            return False
        (self.stack[-1]['children'] if self.stack else self.root).append(item)
        self.nodes += 1
        return True

    def handle_starttag(self, tag, attrs):
        self.attributes += len(attrs)
        if self.truncated:
            return
        if self.suppressed:
            if tag not in HTML_VOID:
                if len(self.suppressed) >= MAX_DEPTH:
                    self.truncated = True
                else:
                    self.suppressed.append(tag)
            return
        if tag in DROP:
            self.omitted[tag] += 1
            if tag not in HTML_VOID:
                self.suppressed.append(tag)
            return
        if tag not in TAGS:
            self.omitted[tag] += 1
            return  # Unknown wrappers and links become text/allowed children.
        if len(self.stack) >= MAX_DEPTH:
            self.truncated = True
            return
        item = {'tag': tag, 'children': []}
        if self.append(item) and tag not in VOID:
            self.stack.append(item)

    def handle_endtag(self, tag):
        if self.suppressed:
            if tag in self.suppressed:
                del self.suppressed[len(self.suppressed)-1-self.suppressed[::-1].index(tag):]
            return
        for i in range(len(self.stack)-1, -1, -1):
            if self.stack[i]['tag'] == tag:
                del self.stack[i:]
                break

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data):
        if not self.suppressed and not self.truncated and data:
            self.append(data)


def project_content(recovered):
    """Return JSON safe to render via createElement/createTextNode only.

    Must be called after the existing content authorization and hash checks.
    The output contains unmasked captured text and needs identical protection.
    """
    if recovered.get('is_html') is not True or recovered.get('verification') != 'capture_sha256_reverified':
        raise ValueError('Verified HTML response source required')
    source = recovered['text']
    if not isinstance(source, str) or len(source.encode('utf-8')) > MAX_INPUT_BYTES:
        raise ValueError('Static projection input exceeds 64 KiB UTF-8')
    parser = _Projection()
    parser.feed(source)
    parser.close()
    return {'representation': 'inert_structure_text_v1', 'nodes': parser.root,
            'source_status': recovered['status'], 'projection_truncated': parser.truncated,
            'node_count': parser.nodes, 'omitted_elements': dict(sorted(parser.omitted.items())),
            'attributes_discarded': parser.attributes, 'resources_recovered': 0,
            'resource_policy': 'none_fetched_or_embedded',
            'limitations': ['lossy_structure_and_text_not_original_browser_layout',
                            'all_attributes_css_scripts_and_resource_references_omitted',
                            'malformed_html_uses_python_parser_not_browser_dom_rules'] +
                           (['projection_node_or_depth_limit'] if parser.truncated else [])}


def export_document(projection):
    """Standalone static artifact from our generated tree, never raw HTML."""
    def render(node):
        if isinstance(node, str):
            return escape(node, quote=True)
        tag = node['tag']
        if tag not in TAGS:
            raise ValueError('Unexpected projection element')
        return '<'+tag+'>'+('' if tag in VOID else ''.join(render(c) for c in node['children'])+'</'+tag+'>')
    return ('<!doctype html><html><head><meta charset="utf-8">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
            'script-src \'none\'; style-src \'none\'; img-src \'none\'; '
            'connect-src \'none\'; object-src \'none\'; base-uri \'none\'; form-action \'none\'">'
            '<title>TRACE captured HTML — inert text and structure</title></head><body>'
            '<h1>Captured HTML: lossy static representation</h1>'
            '<p>TRACE annotation: captured text and allowed structure only. No scripts, CSS, '
            'images, links or external resources. This is not the original webpage appearance.</p>'
            + ('<p>Partial source or projection: content is incomplete.</p>'
               if projection['source_status'] != 'recovered' or projection['projection_truncated'] else '')
            + '<hr>'+''.join(render(n) for n in projection['nodes'])+'</body></html>')
