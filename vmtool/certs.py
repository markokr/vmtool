"""Use internal CA to generate key and certificate.
"""

from configparser import ConfigParser, ExtendedInterpolation
import sysca


__all__ = ['load_cert_config']


def load_cert_config(fn, load_ca, defs):
    cf = ConfigParser(defaults=defs, interpolation=ExtendedInterpolation(),
                      delimiters=['='], comment_prefixes=['#'], inline_comment_prefixes=['#'])
    cf.read([fn])
    return process_config(cf, load_ca)


def process_config(cf, load_ca):
    r"""process already loaded config
    """
    res = {}
    for kname in cf.sections():
        sect = dict(cf.items(kname))

        days = int(sect.get('days', '730'))
        ktype = sect.get('ktype', 'ec')
        alt_names = sect.get('alt_names')

        subject = sect.get('subject')
        if not subject:
            subject = {}
            common_name = sect.get('common_name')
            if not common_name:
                common_name = kname
            common_name = common_name.rstrip('.')
            subject['CN'] = common_name

            sysfe_grants = sect.get('sysfe_grants')
            if sysfe_grants:
                sysfe_clean = []
                for rpcname in sysfe_grants.split(','):
                    rpcname = rpcname.strip()
                    if rpcname:
                        sysfe_clean.append(rpcname)
                subject['OU'] = ':'.join(sysfe_clean)

            if not alt_names:
                if '.' in common_name:
                    if '@' not in common_name:
                        alt_names = ['dns:' + common_name]

        ca_name = sect['ca_name']
        ca_key_fn, ca_cert_fn = load_ca(ca_name)
        ca_key = sysca.load_key(ca_key_fn)
        ca_cert = sysca.load_cert(ca_cert_fn)

        usage = sect.get('usage')
        if not usage:
            usage = ['client']

        inf = sysca.CertInfo(subject=subject, usage=usage, alt_names=alt_names)

        tmp = ktype.split(':', 1)
        ktype = tmp[0]
        kparam = None
        if len(tmp) > 1:
            kparam = tmp[1]

        if ktype == 'ec':
            key = sysca.new_ec_key(kparam or 'secp256r1')
        elif ktype == 'rsa':
            bits = 2048
            if kparam:
                bits = int(kparam)
            key = sysca.new_rsa_key(bits)
        else:
            raise Exception('unknown key type: ' + ktype)

        cert = sysca.create_x509_cert(ca_key, key.public_key(), inf, ca_cert, days)

        pem_key = sysca.key_to_pem(key)
        pem_cert = sysca.cert_to_pem(cert)
        res[kname] = (pem_key, pem_cert)
    return res

