import logging
from functools import partial
try:
    from html.parser import HTMLParseError
    from html.parser import HTMLParser
except ImportError:
    from HTMLParser import HTMLParseError
    from HTMLParser import HTMLParser

import tinycss
log = logging.getLogger("spambayes")

HTML_COLORS = {
    'transparent': (0, 0, 0, 0),
    'aliceblue': (240, 248, 255, 255),
    'antiquewhite': (250, 235, 215, 255),
    'aqua': (0, 255, 255, 255),
    'aquamarine': (127, 255, 212, 255),
    'azure': (240, 255, 255, 255),
    'beige': (245, 245, 220, 255),
    'bisque': (255, 228, 196, 255),
    'black': (0, 0, 0, 255),
    'blanchedalmond': (255, 235, 205, 255),
    'blue': (0, 0, 255, 255),
    'blueviolet': (138, 43, 226, 255),
    'brown': (165, 42, 42, 255),
    'burlywood': (222, 184, 135, 255),
    'cadetblue': (95, 158, 160, 255),
    'chartreuse': (127, 255, 0, 255),
    'chocolate': (210, 105, 30, 255),
    'coral': (255, 127, 80, 255),
    'cornflowerblue': (100, 149, 237, 255),
    'cornsilk': (255, 248, 220, 255),
    'crimson': (220, 20, 60, 255),
    'cyan': (0, 255, 255, 255),
    'darkblue': (0, 0, 139, 255),
    'darkcyan': (0, 139, 139, 255),
    'darkgoldenrod': (184, 134, 11, 255),
    'darkgray': (169, 169, 169, 255),
    'darkgrey': (169, 169, 169, 255),
    'darkgreen': (0, 100, 0, 255),
    'darkkhaki': (189, 183, 107, 255),
    'darkmagenta': (139, 0, 139, 255),
    'darkolivegreen': (85, 107, 47, 255),
    'darkorange': (255, 140, 0, 255),
    'darkorchid': (153, 50, 204, 255),
    'darkred': (139, 0, 0, 255),
    'darksalmon': (233, 150, 122, 255),
    'darkseagreen': (143, 188, 143, 255),
    'darkslateblue': (72, 61, 139, 255),
    'darkslategray': (47, 79, 79, 255),
    'darkslategrey': (47, 79, 79, 255),
    'darkturquoise': (0, 206, 209, 255),
    'darkviolet': (148, 0, 211, 255),
    'deeppink': (255, 20, 147, 255),
    'deepskyblue': (0, 191, 255, 255),
    'dimgray': (105, 105, 105, 255),
    'dimgrey': (105, 105, 105, 255),
    'dodgerblue': (30, 144, 255, 255),
    'firebrick': (178, 34, 34, 255),
    'floralwhite': (255, 250, 240, 255),
    'forestgreen': (34, 139, 34, 255),
    'fuchsia': (255, 0, 255, 255),
    'gainsboro': (220, 220, 220, 255),
    'ghostwhite': (248, 248, 255, 255),
    'gold': (255, 215, 0, 255),
    'goldenrod': (218, 165, 32, 255),
    'gray': (128, 128, 128, 255),
    'grey': (128, 128, 128, 255),
    'green': (0, 128, 0, 255),
    'greenyellow': (173, 255, 47, 255),
    'honeydew': (240, 255, 240, 255),
    'hotpink': (255, 105, 180, 255),
    'indianred ': (205, 92, 92, 255),
    'indigo ': (75, 0, 130, 255),
    'ivory': (255, 255, 240, 255),
    'khaki': (240, 230, 140, 255),
    'lavender': (230, 230, 250, 255),
    'lavenderblush': (255, 240, 245, 255),
    'lawngreen': (124, 252, 0, 255),
    'lemonchiffon': (255, 250, 205, 255),
    'lightblue': (173, 216, 230, 255),
    'lightcoral': (240, 128, 128, 255),
    'lightcyan': (224, 255, 255, 255),
    'lightgoldenrodyellow': (250, 250, 210, 255),
    'lightgray': (211, 211, 211, 255),
    'lightgrey': (211, 211, 211, 255),
    'lightgreen': (144, 238, 144, 255),
    'lightpink': (255, 182, 193, 255),
    'lightsalmon': (255, 160, 122, 255),
    'lightseagreen': (32, 178, 170, 255),
    'lightskyblue': (135, 206, 250, 255),
    'lightslategray': (119, 136, 153, 255),
    'lightslategrey': (119, 136, 153, 255),
    'lightsteelblue': (176, 196, 222, 255),
    'lightyellow': (255, 255, 224, 255),
    'lime': (0, 255, 0, 255),
    'limegreen': (50, 205, 50, 255),
    'linen': (250, 240, 230, 255),
    'magenta': (255, 0, 255, 255),
    'maroon': (128, 0, 0, 255),
    'mediumaquamarine': (102, 205, 170, 255),
    'mediumblue': (0, 0, 205, 255),
    'mediumorchid': (186, 85, 211, 255),
    'mediumpurple': (147, 112, 219, 255),
    'mediumseagreen': (60, 179, 113, 255),
    'mediumslateblue': (123, 104, 238, 255),
    'mediumspringgreen': (0, 250, 154, 255),
    'mediumturquoise': (72, 209, 204, 255),
    'mediumvioletred': (199, 21, 133, 255),
    'midnightblue': (25, 25, 112, 255),
    'mintcream': (245, 255, 250, 255),
    'mistyrose': (255, 228, 225, 255),
    'moccasin': (255, 228, 181, 255),
    'navajowhite': (255, 222, 173, 255),
    'navy': (0, 0, 128, 255),
    'oldlace': (253, 245, 230, 255),
    'olive': (128, 128, 0, 255),
    'olivedrab': (107, 142, 35, 255),
    'orange': (255, 165, 0, 255),
    'orangered': (255, 69, 0, 255),
    'orchid': (218, 112, 214, 255),
    'palegoldenrod': (238, 232, 170, 255),
    'palegreen': (152, 251, 152, 255),
    'paleturquoise': (175, 238, 238, 255),
    'palevioletred': (219, 112, 147, 255),
    'papayawhip': (255, 239, 213, 255),
    'peachpuff': (255, 218, 185, 255),
    'peru': (205, 133, 63, 255),
    'pink': (255, 192, 203, 255),
    'plum': (221, 160, 221, 255),
    'powderblue': (176, 224, 230, 255),
    'purple': (128, 0, 128, 255),
    'rebeccapurple': (102, 51, 153, 255),
    'red': (255, 0, 0, 255),
    'rosybrown': (188, 143, 143, 255),
    'royalblue': (65, 105, 225, 255),
    'saddlebrown': (139, 69, 19, 255),
    'salmon': (250, 128, 114, 255),
    'sandybrown': (244, 164, 96, 255),
    'seagreen': (46, 139, 87, 255),
    'seashell': (255, 245, 238, 255),
    'sienna': (160, 82, 45, 255),
    'silver': (192, 192, 192, 255),
    'skyblue': (135, 206, 235, 255),
    'slateblue': (106, 90, 205, 255),
    'slategray': (112, 128, 144, 255),
    'slategrey': (112, 128, 144, 255),
    'snow': (255, 250, 250, 255),
    'springgreen': (0, 255, 127, 255),
    'steelblue': (70, 130, 180, 255),
    'tan': (210, 180, 140, 255),
    'teal': (0, 128, 128, 255),
    'thistle': (216, 191, 216, 255),
    'tomato': (255, 99, 71, 255),
    'turquoise': (64, 224, 208, 255),
    'violet': (238, 130, 238, 255),
    'wheat': (245, 222, 179, 255),
    'white': (255, 255, 255, 255),
    'whitesmoke': (245, 245, 245, 255),
    'yellow': (255, 255, 0, 255),
    'yellowgreen': (154, 205, 50, 255)
}


class Color(object):
    def __init__(self, r, g, b, a=255):
        self.r = r
        self.g = g
        self.b = b
        self.a = a

    def __str__(self):
        return "(%s, %s, %s, %s)" % (self.r, self.g, self.b, self.a)

    def __repr__(self):
        return "(%s, %s, %s, %s)" % (self.r, self.g, self.b, self.a)

    def __eq__(self, c):
        # XXX This could be improved to check for contrast
        return (abs(self.r - c.r) + abs(self.g - c.g) + abs(self.b - c.b))/3.0 < 40

    def __sub__(self, c):
        return (abs(self.r - c.r) + abs(self.g - c.g) + abs(self.b - c.b))/3.0

    @classmethod
    def from_hex(cls, hexcode):
        try:
            if len(hexcode) == 4:
                return cls(
                    int(2 * hexcode[1], 16),
                    int(2 * hexcode[2], 16),
                    int(2 * hexcode[3], 16)
                )
            else:
                return cls(
                    int(hexcode[1:3], 16),
                    int(hexcode[3:5], 16),
                    int(hexcode[5:7], 16)
                )
        except ValueError:
            log.info("Invalid hexcode %s" % hexcode)
            return cls(255, 255, 255)

    @classmethod
    def from_name(cls, name):
        if name.lower() not in HTML_COLORS:
            return None
        return cls(*HTML_COLORS[name.lower()])

    @property
    def is_transparent(self):
        return self.a < 100

class Style(object):
    """Describes the css style for elements that affect the visibility 
    of an object
    """
    style_parsers = (
        "parse_colors",
        "parse_position",
        "parse_opacity",
        "parse_font",
        "parse_display",
        "parse_visibility"
    )

    def __init__(self, max_offset, min_opacity, min_size, min_color_difference):
        self.max_offset = max_offset
        self.min_opacity = min_opacity
        self.min_size = min_size
        self.min_color_difference = min_color_difference
        self.top = 0
        self.right = 0
        self.bottom = 0
        self.left = 0
        self.text_indent = 0
        self.bg = Color(255, 255, 255)
        self.fg = Color(0, 0, 0)
        self.opacity = 1.0
        self.font = None
        self.size = 12
        self.display = True
        self.visibility = True

    def _parse_size(self, token, current):
        if token.type in ('INTEGER', 'NUMBER'):
            return float(token.value)
        if token.type == "PERCENTAGE":
            return float(token.value * current / 100)
        if token.type == 'DIMENSION':
            if token.unit in ('px', 'pt'):
                return float(token.value)
            elif token.unit in ('rem', 'em'):
                return float(token.value * current)
        return current

    @classmethod
    def from_obj(cls, obj):
        """Get a copy of the given style"""
        new = cls(obj.max_offset, obj.min_opacity, obj.min_size,
                  obj.min_color_difference)
        new.__dict__ = obj.__dict__.copy()
        return new

    def _parse_color(self, token):
        """Checks the possible tinycss token types and gets the correct color
        
        :param token: tinycss token 
        :return: Color instance
        """
        color = None
        if token.type == 'FUNCTION' and token.function_name in ('rgb', 'rgba'):
            try:
                color = Color(
                    *[c.value for c in token.content if c.type == 'INTEGER']
                )
            except TypeError:
                log.error("Couldn't make %r into a colour: %s", token.content,
                          [c.value for c in token.content
                           if c.type == 'INTEGER'])
        if token.type == 'HASH':
            color = Color.from_hex(token.value)
        if token.type == 'IDENT':
            color = Color.from_name(token.value)
        return color

    def parse_colors(self, style):
        """Sets the background and foreground colors based on the style
        
        :param style: tiny css parsed style
        :return: None
        """
        if style.name in ['background-color', 'background']:
            if style.value[0] != "#transparent":
                bg = self._parse_color(style.value[0])
                if bg and bg.a >= self.min_opacity:
                    self.bg = bg

        if style.name == 'color':
            try:
                if style.value[0] == "#transparent":
                    self.fg = self.bg
                else:
                    self.fg = self._parse_color(style.value[0]) or self.fg
            except TypeError:
                log.info("Couldn't compare colour: %r", style.value[0])

    def parse_position(self, style):
        """ if this is a position related style then save the numeric position
        :param style: tiny css parsed style
        :return: None
        """
        if style.name in ['top', 'bottom', 'left', 'right', 'text-indent']:
            name = style.name.replace('-', '_')
            current = getattr(self, name)
            setattr(self, name, self._parse_size(style.value[0], current))

    def parse_opacity(self, style):
        """ if this is an opacity related style the save that opacity
        :param style:  tiny css parsed style
        :return: None
        """
        if style.name == 'opacity':
            if style.value[0].type in ('NUMBER', 'INTEGER'):
                setattr(self, style.name, float(style.value[0].value))

    def parse_display(self, style):
        """ if display is set to None then never set to anything
         else for child elements
        :param style:  tiny css parsed style
        :return: None
        """
        if style.name == 'display':
            value = style.value[0]
            if value.type == 'IDENT' and value.value.lower() == 'none':
                self.display = False

    def parse_visibility(self, style):
        if style.name == 'visibility':
            value = style.value[0]
            if not hasattr(value.value, "lower"):
                # Likely a number. Assume visible for now.
                self.visibility = True
            elif value.value.lower() in ('visible', 'initial'):
                self.visibility = True
            elif value.value.lower() == 'hidden':
                self.visibility = False

    def parse_font(self, style):
        """Gets the font size for the specific style
        :param style:  tiny css parsed style
        :return: None
        """
        if style.name == 'font-size':
            self.size = self._parse_size(style.value[0], self.size)

    def parse_css(self, css):
        """Takes an inline css string and iterates through the style parsers
        :param css:  string
        :return: None
        
        """
        if not css:
            return
        styles = tinycss.CSS21Parser().parse_style_attr(css)[0]

        for style in styles:
            for parser in self.style_parsers:
                getattr(self, parser)(style)

    @property
    def visible(self):
        """Evaluates whether the current style should be considered invisible
        :return: bool
        """
        if not self.display:
            return False, "display"

        if not self.visibility:
            return False, "visibility"

        if self.size < self.min_size:
            log.debug("font-size is too small %s", self.size)
            return False, "font-size"

        if self.fg - self.bg < self.min_color_difference:
            log.debug("difference between colors too small %s - %s = %s ", self.fg, self.bg, self.fg - self.bg)
            return False, "colors"

        if self.fg.a/255.0 < self.min_opacity or self.opacity < self.min_opacity:
            log.debug("opacity is too small fg alpha %s, opacity %s, min %s", self.fg.a, self.opacity, self.min_opacity)
            return False, "opacity"

        offset = any(
            not -self.max_offset < getattr(self, x) < self.max_offset
            for x in ['top', 'right', 'bottom', 'left', 'text_indent']
        )
        if offset:
            return False, "offset"

        return True, None

    def __repr__(self):
        return str(self.__dict__)


class InvisibleStyleParser(HTMLParser):
    visible_size = 0
    invisible_size = 0
    open_tags = 0
    closed_tags = 0

    def __init__(self, base_style, include_comments=True):
        self.raw_html = ''
        self.style_stack = []
        self.invisible_elements = []
        self._parsed = []
        self.include_comments = include_comments
        self.positions = []
        self.base_style = base_style
        self.style_stack.append(("", self.base_style))
        HTMLParser.__init__(self)

    @property
    def ratio(self):
        try:
            return self.invisible_size/float(self.visible_size)
        except ZeroDivisionError:
            return float('inf')

    @staticmethod
    def create_starttag(tag, attrs):
        return "<%s %s>" % (tag, " ".join(['%s="%s"' % (k, v) for k, v in attrs]))

    @staticmethod
    def create_endtag(tag):
        return "<%s>" % tag

    @staticmethod
    def create_startendtag(tag, attrs):
        return "<%s %s/>" % (tag, " ".join(['%s="%s"' % (k, v) for k, v in attrs]))

    @staticmethod
    def create_data(data):
        return data

    def handle_starttag(self, tag, attrs):
        self._parsed.append(partial(self.create_starttag, tag, attrs))
        style = Style.from_obj(self.style_stack[-1][1])
        attrs = dict(attrs or [])
        if "hidden" in attrs:
            style.display = False
        style.parse_css(attrs.get('style', ''))
        if tag == "font" and "color" in attrs:
            style.fg = Color.from_hex(attrs["color"])
        self.style_stack.append((tag, style))

    def handle_data(self, data):
        clear_data = data.strip()
        visible, prop = self.style_stack[-1][1].visible
        if not visible and clear_data:
            self.invisible_size += len(clear_data)
            self.invisible_elements.append((len(clear_data), prop))
        else:
            if clear_data:
                self._parsed.append(partial(self.create_data, clear_data))
            self.visible_size += len(clear_data)

    def handle_startendtag(self, tag, attrs):
        self._parsed.append(partial(self.create_startendtag, tag, attrs))

    def handle_comment(self, data):
        if self.include_comments:
            self.invisible_size += len(data.strip())
            self.invisible_elements.append((len(data), "comment"))

    def handle_endtag(self, tag):
        self._parsed.append(partial(self.create_endtag, tag))
        if self.style_stack[-1][0] == tag:
            try:
                self.style_stack.pop()
            except IndexError:
                pass

    @staticmethod
    def create_charref(name):
        return "&#%s;" % name

    def handle_charref(self, name):
        self._parsed.append(partial(self.create_charref, name))

    @staticmethod
    def create_entityref(name):
        return "&%s;" % name

    def handle_entityref(self, name):
        self._parsed.append(partial(self.create_entityref, name))

    @staticmethod
    def create_decl(data):
        return "<! %s>" % data

    def handle_decl(self, decl):
        self._parsed.append(partial(self.create_decl, decl))

    @staticmethod
    def create_pi_tag(data):
        return "<? %s >" % data

    def handle_pi(self, data):
        self._parsed.append(partial(self.create_pi_tag, data))

    @property
    def parsed(self):
        return "\n".join([x() for x in self._parsed])


def replace_invisible_elements(html, min_size, min_opacity,
                               min_color_difference, max_offset, min_ratio=0):
    """Replaces the invisible strings in a html document
    :param html: string containing html
    :param min_size: int minimum font size for an element to be invisible
    :param min_opacity: float minimum opacity for an element to be invisible
    :param min_color_difference: minimum average channel difference 
    for an element to be invisible
    :param max_offset: maximum positive/negative offset for an element to be 
    considered visible
    :param min_ratio: ratio of invisible / visible text required for replacement
     to occur
    :return: str, bool
    """
    style = Style(
        min_opacity=min_opacity,
        min_size=min_size,
        min_color_difference=min_color_difference,
        max_offset=max_offset
    )
    parser = InvisibleStyleParser(style)
    tokens = []
    try:
        parser.feed(html)
    except HTMLParseError:
        # We'll just have to return the original.
        tokens.append("nightvision:unparseable-html")
        return html, tokens
    if parser.ratio > min_ratio:
        html = parser.parsed
        tokens = parser.invisible_elements
    return html, tokens

