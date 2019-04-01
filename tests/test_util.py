
def test_strconv():
    from vmtool.util import as_unicode, as_bytes

    assert isinstance(as_unicode(b''), str)
    assert isinstance(as_unicode(u''), str)
    assert isinstance(as_bytes(b''), bytes)
    assert isinstance(as_bytes(u''), bytes)


def test_hash_host():
    from vmtool.util import hash_known_host

    assert hash_known_host('some.host.com', '|1|pzMIu+gxkwsr5matTvsO4KHd0os=|p57KT8xgV5ajb4mLNWvGUIvrAps=') \
        == '|1|pzMIu+gxkwsr5matTvsO4KHd0os=|p57KT8xgV5ajb4mLNWvGUIvrAps='
    assert hash_known_host('other.host.com', '|1|pzMIu+gxkwsr5matTvsO4KHd0os=|p57KT8xgV5ajb4mLNWvGUIvrAps=') \
        == '|1|pzMIu+gxkwsr5matTvsO4KHd0os=|7At8Sio5/hZt8099y94J7JWsXTY='


def test_fmt_dur():
    from vmtool.util import fmt_dur

    assert fmt_dur(0.001) == '0s'
    assert fmt_dur(1.1) == '1s'
    assert fmt_dur(((27 * 24 + 2) * 60 + 38) * 60 + 43) == '27d2h38m43s'
    assert fmt_dur(-5) == '-5s'


def test_rsh_quote():
    from vmtool.util import rsh_quote

    assert rsh_quote(["a", "-b=/x", ]) == ["a", "-b=/x"]
    assert rsh_quote(["a\"b", "a$b", "a b", "a'b"]) == ["'a\"b'", "'a$b'", "'a b'", r"'a'\''b'"]


_sample_console = '''
ec2: #############################################################
ec2: -----BEGIN SSH HOST KEY FINGERPRINTS-----
ec2: 1024 51:1f:48:85:32:68:a5:09:65:e8:e8:8e:18:17:9a:96  root@ip-10-64-5-176 (DSA)
ec2: 256 1b:12:a7:f6:ce:77:3d:a7:3f:f6:85:95:19:aa:28:a0  root@ip-10-64-5-176 (ECDSA)
ec2: 2048 2d:d5:4b:67:d9:66:a2:20:77:19:55:0b:05:ff:01:1c  root@ip-10-64-5-176 (RSA)
ec2: -----END SSH HOST KEY FINGERPRINTS-----
ec2: #############################################################
-----BEGIN SSH HOST KEY KEYS-----
ecdsa-sha2-nistp256 ...... root@foo
[xxx]ssh-rsa ...... root@foo
-----END SSH HOST KEY KEYS-----
'''

def test_parse_console():
    from vmtool.util import parse_console

    assert parse_console(_sample_console) == [('ecdsa-sha2-nistp256', '......')]

