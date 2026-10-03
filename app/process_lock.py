"""Enforce one scheduler per data directory, including across processes."""
import os


class ProcessLock:
    def __init__(self,path):
        self.file=open(path,'a+b')
        if os.name=='nt':
            import msvcrt
            self.file.seek(0,2)
            if self.file.tell()==0:
                self.file.write(b'0');self.file.flush()
            self.file.seek(0)
            try:
                msvcrt.locking(self.file.fileno(),msvcrt.LK_NBLCK,1)
            except OSError:
                self.file.close()
                raise RuntimeError('Eine andere Instanz verwendet bereits dieses Datenverzeichnis') from None
        else:
            import fcntl
            try:
                fcntl.flock(self.file.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            except OSError:
                self.file.close()
                raise RuntimeError('Eine andere Instanz verwendet bereits dieses Datenverzeichnis') from None

    def close(self):
        if self.file.closed:
            return
        if os.name=='nt':
            import msvcrt
            self.file.seek(0);msvcrt.locking(self.file.fileno(),msvcrt.LK_UNLCK,1)
        else:
            import fcntl
            fcntl.flock(self.file.fileno(),fcntl.LOCK_UN)
        self.file.close()
