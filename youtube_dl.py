import urllib2
import time
import re
import json
import operator

USER_AGENT = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.115 Safari/537.36'

_formats = {
        '18': {'ext': 'mp4', 'width': 640, 'height': 360, 'acodec': 'aac', 'abr': 96, 'vcodec': 'h264'},
        '22': {'ext': 'mp4', 'width': 1280, 'height': 720, 'acodec': 'aac', 'abr': 192, 'vcodec': 'h264'},
        '36': {'ext': '3gp', 'width': 320, 'acodec': 'aac', 'vcodec': 'mp4v'},
}

NO_DEFAULT = object()

compat_str = unicode

compiled_regex_type = type(re.compile(''))

def _search_regex(pattern, string, name, default=NO_DEFAULT, fatal=True, flags=0, group=None):
    if isinstance(pattern, (str, compat_str, compiled_regex_type)):
        mobj = re.search(pattern, string, flags)
    else:
        for p in pattern:
            mobj = re.search(p, string, flags)
            if mobj:
                break
    if mobj:
        if group is None:
            return next(g for g in mobj.groups() if g is not None)
        else:
            return mobj.group(group)
    elif default is not NO_DEFAULT:
        return default
    elif fatal:
        raise Exception('Unable to extract %s' % name)
    else:
        return None


try:
    import urllib.parse as compat_urllib_parse
except ImportError:  # Python 2
    import urllib as compat_urllib_parse

try:
    from urllib.parse import unquote_to_bytes as compat_urllib_parse_unquote_to_bytes
    from urllib.parse import unquote as compat_urllib_parse_unquote
    from urllib.parse import unquote_plus as compat_urllib_parse_unquote_plus
except ImportError:  # Python 2
    _asciire = (compat_urllib_parse._asciire if hasattr(compat_urllib_parse, '_asciire')
                else re.compile(r'([\x00-\x7f]+)'))

    # HACK: The following are the correct unquote_to_bytes, unquote and unquote_plus
    # implementations from cpython 3.4.3's stdlib. Python 2's version
    # is apparently broken (see https://github.com/rg3/youtube-dl/pull/6244)

    def compat_urllib_parse_unquote_to_bytes(string):
        """unquote_to_bytes('abc%20def') -> b'abc def'."""
        # Note: strings are encoded as UTF-8. This is only an issue if it contains
        # unescaped non-ASCII characters, which URIs should not.
        if not string:
            # Is it a string-like object?
            string.split
            return b''
        if isinstance(string, compat_str):
            string = string.encode('utf-8')
        bits = string.split(b'%')
        if len(bits) == 1:
            return string
        res = [bits[0]]
        append = res.append
        for item in bits[1:]:
            try:
                append(compat_urllib_parse._hextochr[item[:2]])
                append(item[2:])
            except KeyError:
                append(b'%')
                append(item)
        return b''.join(res)

    def compat_urllib_parse_unquote(string, encoding='utf-8', errors='replace'):
        """Replace %xx escapes by their single-character equivalent. The optional
        encoding and errors parameters specify how to decode percent-encoded
        sequences into Unicode characters, as accepted by the bytes.decode()
        method.
        By default, percent-encoded sequences are decoded with UTF-8, and invalid
        sequences are replaced by a placeholder character.

        unquote('abc%20def') -> 'abc def'.
        """
        if '%' not in string:
            string.split
            return string
        if encoding is None:
            encoding = 'utf-8'
        if errors is None:
            errors = 'replace'
        bits = _asciire.split(string)
        res = [bits[0]]
        append = res.append
        for i in range(1, len(bits), 2):
            append(compat_urllib_parse_unquote_to_bytes(bits[i]).decode(encoding, errors))
            append(bits[i + 1])
        return ''.join(res)

    def compat_urllib_parse_unquote_plus(string, encoding='utf-8', errors='replace'):
        """Like unquote(), but also replace plus signs by spaces, as required for
        unquoting HTML form values.

        unquote_plus('%7e/abc+def') -> '~/abc def'
        """
        string = string.replace('+', ' ')
        return compat_urllib_parse_unquote(string, encoding, errors)

try:
    from urllib.parse import urlencode as compat_urllib_parse_urlencode
except ImportError:
    def compat_urllib_parse_urlencode(query, doseq=0, encoding='utf-8'):
        def encode_elem(e):
            if isinstance(e, dict):
                e = encode_dict(e)
            elif isinstance(e, (list, tuple,)):
                list_e = encode_list(e)
                e = tuple(list_e) if isinstance(e, tuple) else list_e
            elif isinstance(e, compat_str):
                e = e.encode(encoding)
            return e

        def encode_dict(d):
            return dict((encode_elem(k), encode_elem(v)) for k, v in d.items())

        def encode_list(l):
            return [encode_elem(e) for e in l]

        return compat_urllib_parse.urlencode(encode_elem(query), doseq=doseq)

def _parse_qsl(qs, keep_blank_values=False, strict_parsing=False,
                   encoding='utf-8', errors='replace'):
    qs, _coerce_result = qs, compat_str
    pairs = [s2 for s1 in qs.split('&') for s2 in s1.split(';')]
    r = []
    for name_value in pairs:
        if not name_value and not strict_parsing:
                continue
        nv = name_value.split('=', 1)
        if len(nv) != 2:
            if strict_parsing:
                    raise Exception('bad query field: %r' % (name_value,))
            # Handle case of a control-name with no equal sign
            if keep_blank_values:
                nv.append('')
            else:
                continue
        if len(nv[1]) or keep_blank_values:
            name = nv[0].replace('+', ' ')
            name = compat_urllib_parse_unquote(name, encoding=encoding, errors=errors)
            name = _coerce_result(name)
            value = nv[1].replace('+', ' ')
            value = compat_urllib_parse_unquote(value, encoding=encoding, errors=errors)
            value = _coerce_result(value)
            r.append((name, value))
    return r

def compat_parse_qs(qs, keep_blank_values=False, strict_parsing=False,
                        encoding='utf-8', errors='replace'):
    parsed_result = {}
    pairs = _parse_qsl(qs, keep_blank_values, strict_parsing, encoding=encoding, errors=errors)
    for name, value in pairs:
        if name in parsed_result:
            parsed_result[name].append(value)
        else:
            parsed_result[name] = [value]
    return parsed_result


def download_webpage(url):
    headers = {'User-Agent': USER_AGENT}
    request = urllib2.Request(url, headers = headers)
    res = urllib2.urlopen(request)
    html = res.read()
    return html

    
def _get_ytplayer_config(video_id, webpage):
    patterns = (
        # User data may contain arbitrary character sequences that may affect
        # JSON extraction with regex, e.g. when '};' is contained the second
        # regex won't capture the whole JSON. Yet working around by trying more
        # concrete regex first keeping in mind proper quoted string handling
        # to be implemented in future that will replace this workaround (see
        # https://github.com/rg3/youtube-dl/issues/7468,
        # https://github.com/rg3/youtube-dl/pull/7599)
        r';ytplayer\.config\s*=\s*({.+?});ytplayer',
        r';ytplayer\.config\s*=\s*({.+?});',
    )
    config = _search_regex(patterns, webpage, 'ytplayer.config', default=None)
    if config:
        return _parse_json(config, video_id)

def _parse_json(json_string, video_id):
    try:
        return json.loads(json_string)
    except ValueError as ve:
        errmsg = '%s: Failed to parse JSON ' % video_id


def read_extract(video_id):
    url = 'https://www.youtube.com/watch?v=%s&gl=US&hl=en&has_verified=1&bpctr=9999999999' % video_id
    video_webpage = download_webpage(url)
    is_live = None
    embed_webpage = None
    player_response = {}
    result = []
    if re.search(r'player-age-gate-content">', video_webpage) is not None:
        age_gate = True
        url = 'https://www.youtube.com/embed/%s' % video_id
        embed_webpage = download_webpage(url)
        data = compat_urllib_parse_urlencode({
            'video_id': video_id,
            'eurl': 'https://youtube.googleapis.com/v/' + video_id,
            'sts': _search_regex(
                    r'"sts"\s*:\s*(\d+)', embed_webpage, 'sts', default=''),
        })
        video_info_url = 'https://www.youtube.com/get_video_info?' + data
        video_info_webpage = download_webpage(video_info_url)
        video_info = compat_parse_qs(video_info_webpage)
    else:
    	age_gate = False
        video_info = None
        sts = None 
        ytplayer_config = _get_ytplayer_config(video_id, video_webpage)
        if ytplayer_config:
            args = ytplayer_config['args']
            if args.get('url_encoded_fmt_stream_map'):
                video_info = dict((k, [v]) for k, v in args.items())
            if args.get('livestream') == '1' or args.get('live_playback') == 1:
                is_live = True
                sts = ytplayer_config.get('sts')
            if not video_info:
                for el in ('info', 'embedded', 'detailpage', 'vevo', ''):
                    query = {
                        'video_id': video_id, 
                        'ps': 'default', 
                        'eurl': '', 
                        'gl': 'US', 
                        'hl':'en',
                    }
                    if el:
                        query['el'] = el
                    if sts:
                        query['sts'] = sts
                    data = compat_urllib_parse_urlencode(query)
                    video_info_webpage = download_webpage('https://www.youtube.com/get_video_info?' + data)
                    if not video_info_webpage:
                        continue
                    get_video_info = compat_parse_qs(video_info_webpage)
                    if not video_info:
                        video_info = get_video_info
                    if 'token' in get_video_info:
                        if 'token' not in video_info:
                            video_info = get_video_info
                        break
    
    if 'token' not in video_info:
        if 'reason' in video_info:
            reason = video_info['reason'][0]
        else :
            raise Exception('"token" parameter not in video info for unknown reason video_id=%s' % video_id)
    if not is_live and (len(video_info.get('url_encoded_fmt_stream_map', [''])[0]) >= 1 or len(video_info.get('adaptive_fmts', [''])[0]) >= 1):
        encoded_url_map = video_info.get('url_encoded_fmt_stream_map', [''])[0] + ',' + video_info.get('adaptive_fmts', [''])[0]
        formats_spec = {}
        fmt_list = video_info.get('fmt_list', [''])[0]
        if fmt_list:
            for fmt in fmt_list.split(','):
                spec = fmt.split('/')
                if len(spec) > 1:
                    width_height = spec[1].split('x')
                    if len(width_height) == 2:
                        formats_spec[spec[0]] = {
                            'resolution': spec[1],
                            'width':  width_height[0],
                            'height': width_height[1],
                        }
        formats = []
        for url_data_str in encoded_url_map.split(','):
            url_data = compat_parse_qs(url_data_str)
            if 'itag' not in url_data or 'url' not in url_data:
                continue
            format_id = url_data['itag'][0]

            if format_id not in _formats:
                continue

            url = url_data['url'][0]
            
            # print url
            if 's' in url_data:
                ASSETS_RE = r'"assets":.+?"js":\s*("[^"]+")'
                jsplayer_url_json = _search_regex(ASSETS_RE, embed_webpage if age_gate else video_webpage, 'JS player URL (1)')
                if not jsplayer_url_json and not age_gate:
                    if embed_webpage is None:
                        embed_url = 'https://www.youtube.com/embed/%s' % video_id
                        embed_webpage = download_webpage(embed_url)
                        jsplayer_url_json = _search_regex(ASSETS_RE, embed_webpage, 'JS player URL')

                player_url = json.loads(jsplayer_url_json)
                if player_url is None:
                    player_url_json = _search_regex(r'ytplayer\.config.*?"url"\s*:\s*("[^"]+")',
                            video_webpage, 'age gate player URL')
                    player_url = json.loads(player_url_json)

            if 'sig' in url_data:
                url += '&signature=' + url_data['sig'][0]
            elif 's' in url_data:
                encrypted_sig = url_data['s'][0]
                signature = _decrypt_signature(encrypted_sig, video_id, player_url, age_gate)
                url += '&signature=' + signature
                # print 'player_url' + player_url

            if 'ratebypass' not in url:
                url += '&ratebypass=yes'
            
            dct = { 'format_id': format_id, 'url': url}
            if format_id in _formats:
                dct.update(_formats[format_id])
            if format_id in formats_spec:
                dct.update(formats_spec[format_id])
            result.append(dct)
    return json.dumps(result)

_player_cache = {}

def _decrypt_signature(s, video_id, player_url, age_gate):
    if player_url is None:
        raise Exception('Cannot decrypt signature without player_url')

    if player_url.startswith('//'):
        player_url = 'https:' + player_url
    elif not re.match(r'https?://', player_url):
        player_url = 'https://www.youtube.com'+ player_url
    
    try:
        player_id = (player_url, _signature_cache_id(s))
        if player_id not in _player_cache:
            func = _extract_signature_function(video_id, player_url, s)
            _player_cache[player_id] = func
        func = _player_cache[player_id]
        return func(s)
    except Exception as e:
        raise Exception('Signature extraction failed')


def _signature_cache_id(example_sig):
    """ Return a string representation of a signature """
    return '.'.join(compat_str(len(part)) for part in example_sig.split('.'))
    
def _extract_signature_function(video_id, player_url, example_sig):
    id_m = re.match(r'.*?-(?P<id>[a-zA-Z0-9_-]+)(?:/watch_as3|/html5player(?:-new)?|(?:/[a-z]{2,3}_[A-Z]{2})?/base)?\.(?P<ext>[a-z]+)$',
            player_url)
    if not id_m:
        raise Exception('Cannot identify player %r' % player_url)
    player_type = id_m.group('ext')
    player_id = id_m.group('id')
    func_id = '%s_%s_%s' % (player_type, player_id, _signature_cache_id(example_sig))
    # assert os.path.basename(func_id) == func_id
    def _parse_sig_js( jscode):
        funcname = _search_regex(
            (r'(["\'])signature\1\s*,\s*(?P<sig>[a-zA-Z0-9$]+)\(',
             r'\.sig\|\|(?P<sig>[a-zA-Z0-9$]+)\(',
             r'yt\.akamaized\.net/\)\s*\|\|\s*.*?\s*c\s*&&\s*d\.set\([^,]+\s*,\s*(?:encodeURIComponent\s*\()?(?P<sig>[a-zA-Z0-9$]+)\(',
             r'\bc\s*&&\s*d\.set\([^,]+\s*,\s*(?:encodeURIComponent\s*\()?\s*(?P<sig>[a-zA-Z0-9$]+)\(',
             r'\bc\s*&&\s*d\.set\([^,]+\s*,\s*\([^)]*\)\s*\(\s*(?P<sig>[a-zA-Z0-9$]+)\('),
            jscode, 'Initial JS player signature function name', group='sig')

        jsi = JSInterpreter(jscode)
        initial_function = jsi.extract_function(funcname)
        return lambda s: initial_function([s])

    if player_type == 'js':
        code = download_webpage(player_url)
        res = _parse_sig_js(code)
        return res
    else:
        raise Exception('we just support js player')


_OPERATORS = [
    ('|', operator.or_),
    ('^', operator.xor),
    ('&', operator.and_),
    ('>>', operator.rshift),
    ('<<', operator.lshift),
    ('-', operator.sub),
    ('+', operator.add),
    ('%', operator.mod),
    ('/', operator.truediv),
    ('*', operator.mul),
]
_ASSIGN_OPERATORS = [(op + '=', opfunc) for op, opfunc in _OPERATORS]
_ASSIGN_OPERATORS.append(('=', lambda cur, right: right))

_NAME_RE = r'[a-zA-Z_$][a-zA-Z_$0-9]*'

def remove_quotes(s):
    if s is None or len(s) < 2:
        return s
    for quote in ('"', "'", ):
        if s[0] == quote and s[-1] == quote:
            return s[1:-1]
    return s


class JSInterpreter(object):
    def __init__(self, code, objects=None):
        if objects is None:
            objects = {}
        self.code = code
        self._functions = {}
        self._objects = objects

    def interpret_statement(self, stmt, local_vars, allow_recursion=100):
        if allow_recursion < 0:
            raise Exception('Recursion limit reached')

        should_abort = False
        stmt = stmt.lstrip()
        stmt_m = re.match(r'var\s', stmt)
        if stmt_m:
            expr = stmt[len(stmt_m.group(0)):]
        else:
            return_m = re.match(r'return(?:\s+|$)', stmt)
            if return_m:
                expr = stmt[len(return_m.group(0)):]
                should_abort = True
            else:
                # Try interpreting it as an expression
                expr = stmt

        v = self.interpret_expression(expr, local_vars, allow_recursion)
        return v, should_abort

    def interpret_expression(self, expr, local_vars, allow_recursion):
        expr = expr.strip()
        if expr == '':  # Empty expression
            return None

        if expr.startswith('('):
            parens_count = 0
            for m in re.finditer(r'[()]', expr):
                if m.group(0) == '(':
                    parens_count += 1
                else:
                    parens_count -= 1
                    if parens_count == 0:
                        sub_expr = expr[1:m.start()]
                        sub_result = self.interpret_expression(
                            sub_expr, local_vars, allow_recursion)
                        remaining_expr = expr[m.end():].strip()
                        if not remaining_expr:
                            return sub_result
                        else:
                            expr = json.dumps(sub_result) + remaining_expr
                        break
            else:
                raise Exception('Premature end of parens in %r' % expr)

        for op, opfunc in _ASSIGN_OPERATORS:
            m = re.match(r'''(?x)
                (?P<out>%s)(?:\[(?P<index>[^\]]+?)\])?
                \s*%s
                (?P<expr>.*)$''' % (_NAME_RE, re.escape(op)), expr)
            if not m:
                continue
            right_val = self.interpret_expression(
                m.group('expr'), local_vars, allow_recursion - 1)

            if m.groupdict().get('index'):
                lvar = local_vars[m.group('out')]
                idx = self.interpret_expression(
                    m.group('index'), local_vars, allow_recursion)
                assert isinstance(idx, int)
                cur = lvar[idx]
                val = opfunc(cur, right_val)
                lvar[idx] = val
                return val
            else:
                cur = local_vars.get(m.group('out'))
                val = opfunc(cur, right_val)
                local_vars[m.group('out')] = val
                return val

        if expr.isdigit():
            return int(expr)

        var_m = re.match(
            r'(?!if|return|true|false)(?P<name>%s)$' % _NAME_RE,
            expr)
        if var_m:
            return local_vars[var_m.group('name')]

        try:
            return json.loads(expr)
        except ValueError:
            pass

        m = re.match(
            r'(?P<in>%s)\[(?P<idx>.+)\]$' % _NAME_RE, expr)
        if m:
            val = local_vars[m.group('in')]
            idx = self.interpret_expression(
                m.group('idx'), local_vars, allow_recursion - 1)
            return val[idx]

        m = re.match(
            r'(?P<var>%s)(?:\.(?P<member>[^(]+)|\[(?P<member2>[^]]+)\])\s*(?:\(+(?P<args>[^()]*)\))?$' % _NAME_RE,
            expr)
        if m:
            variable = m.group('var')
            member = remove_quotes(m.group('member') or m.group('member2'))
            arg_str = m.group('args')

            if variable in local_vars:
                obj = local_vars[variable]
            else:
                if variable not in self._objects:
                    self._objects[variable] = self.extract_object(variable)
                obj = self._objects[variable]

            if arg_str is None:
                # Member access
                if member == 'length':
                    return len(obj)
                return obj[member]

            assert expr.endswith(')')
            # Function call
            if arg_str == '':
                argvals = tuple()
            else:
                argvals = tuple([
                    self.interpret_expression(v, local_vars, allow_recursion)
                    for v in arg_str.split(',')])

            if member == 'split':
                assert argvals == ('',)
                return list(obj)
            if member == 'join':
                assert len(argvals) == 1
                return argvals[0].join(obj)
            if member == 'reverse':
                assert len(argvals) == 0
                obj.reverse()
                return obj
            if member == 'slice':
                assert len(argvals) == 1
                return obj[argvals[0]:]
            if member == 'splice':
                assert isinstance(obj, list)
                index, howMany = argvals
                res = []
                for i in range(index, min(index + howMany, len(obj))):
                    res.append(obj.pop(index))
                return res

            return obj[member](argvals)

        for op, opfunc in _OPERATORS:
            m = re.match(r'(?P<x>.+?)%s(?P<y>.+)' % re.escape(op), expr)
            if not m:
                continue
            x, abort = self.interpret_statement(
                m.group('x'), local_vars, allow_recursion - 1)
            if abort:
                raise Exception(
                    'Premature left-side return of %s in %r' % (op, expr))
            y, abort = self.interpret_statement(
                m.group('y'), local_vars, allow_recursion - 1)
            if abort:
                raise Exception(
                    'Premature right-side return of %s in %r' % (op, expr))
            return opfunc(x, y)

        m = re.match(
            r'^(?P<func>%s)\((?P<args>[a-zA-Z0-9_$,]*)\)$' % _NAME_RE, expr)
        if m:
            fname = m.group('func')
            argvals = tuple([
                int(v) if v.isdigit() else local_vars[v]
                for v in m.group('args').split(',')]) if len(m.group('args')) > 0 else tuple()
            if fname not in self._functions:
                self._functions[fname] = self.extract_function(fname)
            return self._functions[fname](argvals)

        raise Exception('Unsupported JS expression %r' % expr)

    def extract_object(self, objname):
        _FUNC_NAME_RE = r'''(?:[a-zA-Z$0-9]+|"[a-zA-Z$0-9]+"|'[a-zA-Z$0-9]+')'''
        obj = {}
        obj_m = re.search(
            r'''(?x)
                (?<!this\.)%s\s*=\s*{\s*
                    (?P<fields>(%s\s*:\s*function\s*\(.*?\)\s*{.*?}(?:,\s*)?)*)
                }\s*;
            ''' % (re.escape(objname), _FUNC_NAME_RE),
            self.code)
        fields = obj_m.group('fields')
        # Currently, it only supports function definitions
        fields_m = re.finditer(
            r'''(?x)
                (?P<key>%s)\s*:\s*function\s*\((?P<args>[a-z,]+)\){(?P<code>[^}]+)}
            ''' % _FUNC_NAME_RE,
            fields)
        for f in fields_m:
            argnames = f.group('args').split(',')
            obj[remove_quotes(f.group('key'))] = self.build_function(argnames, f.group('code'))

        return obj

    def extract_function(self, funcname):
        func_m = re.search(
            r'''(?x)
                (?:function\s+%s|[{;,]\s*%s\s*=\s*function|var\s+%s\s*=\s*function)\s*
                \((?P<args>[^)]*)\)\s*
                \{(?P<code>[^}]+)\}''' % (
                re.escape(funcname), re.escape(funcname), re.escape(funcname)),
            self.code)
        if func_m is None:
            raise Exception('Could not find JS function %r' % funcname)
        argnames = func_m.group('args').split(',')

        return self.build_function(argnames, func_m.group('code'))

    def call_function(self, funcname, *args):
        f = self.extract_function(funcname)
        return f(args)

    def build_function(self, argnames, code):
        def resf(args):
            local_vars = dict(zip(argnames, args))
            for stmt in code.split(';'):
                res, abort = self.interpret_statement(stmt, local_vars)
                if abort:
                    break
            return res
        return resf


if __name__ == '__main__':
    video_id = '8cmlRYN9FvU'
    print 'start parser video_id : %s' % video_id
    result = read_extract(video_id)
    print result