"""Tarball creation with data filter.
"""

import sys
import io
import os
import tarfile
import time
import stat

__all__ = ['TarBall']

# mode for normal files
TAR_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH

# mode for directories
TAR_DIR_MODE = stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH

# mode for executable files
TAR_EXEC_MODE = TAR_DIR_MODE


class TarBall(object):
    def __init__(self):
        self.buf = io.BytesIO()
        self.tf = tarfile.open('buf.tgz', 'w|gz', self.buf, format=tarfile.PAX_FORMAT)

    def filter_data(self, fname, data):
        """Overridable function."""
        return fname, data

    def add_path(self, path):
        """Add path recursively."""
        for dpath, dnames, fnames in os.walk(path):
            self.add_dir(dpath)
            for fn in fnames:
                fpath = os.path.join(dpath, fn)
                self.add_file(fpath)

    def add_file(self, fpath):
        """Add single file."""
        st = os.lstat(fpath)
        mode = TAR_FILE_MODE
        if st.st_mode & stat.S_IXUSR > 0:
            mode = TAR_EXEC_MODE

        with open(fpath, 'rb') as f:
            data = f.read()

        self.add_file_data(fpath, data, mode)

    def add_file_data(self, fpath, data, mode=TAR_FILE_MODE, mtime=None):
        """Add data as filename."""
        origdata = data
        fpath = fpath.replace('\\', '/')
        fpath, data = self.filter_data(fpath, data)
        if not fpath:
            return
        if data is not origdata:
            mtime = None
        inf = tarfile.TarInfo(fpath)
        inf.mtime = mtime or time.time()
        inf.uid = 1000
        inf.gid = 1000
        inf.uname = 'nobody'
        inf.gname = 'nobody'
        inf.mode = mode

        base = fpath.split('/')[-1]
        ext = None
        if '.' in base:
            ext = base.split('.')[-1]
        if ext == 'sh':
            inf.mode = TAR_EXEC_MODE
        elif base in ('fl_start_services', 'job_setup', 'user_setup'):
            inf.mode = TAR_EXEC_MODE

        inf.size = len(data)

        self.tf.addfile(inf, io.BytesIO(data))

    def add_dir(self, dpath, mode=TAR_DIR_MODE, mtime=None):
        """Add directory entry."""
        dpath = dpath.replace('\\', '/')
        dpath, data = self.filter_data(dpath, None)
        if not dpath:
            return

        inf = tarfile.TarInfo(dpath + '/')
        inf.mtime = mtime or time.time()
        inf.uid = 1000
        inf.gid = 1000
        inf.uname = 'nobody'
        inf.gname = 'nobody'
        inf.mode = mode
        inf.type = tarfile.DIRTYPE
        self.tf.addfile(inf)

    def close(self):
        """Close tarball."""
        if self.tf:
            self.tf.close()
            self.tf = None

    def getvalue(self):
        """Get final result."""
        return self.buf.getvalue()


def main():
    tb = TarBall()
    for fn in sys.argv[1:]:
        tb.add_path(fn)
    tb.close()
    sys.stdout.write(tb.getvalue())
    sys.stdout.flush()


if __name__ == '__main__':
    main()

