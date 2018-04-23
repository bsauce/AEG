#!/usr/bin/env python
import sys
import string
import angr
import subprocess
import re
import lscan

#for lscan to angr
func_list = {'strncmp': 'strncmp', 'rand': 'rand', '_IO_fwrite': 'fwrite', '__munmap': 'munmap', 'memset': 'memset', '_IO_setvbuf': 'setvbuf', '__libc_read': 'read', '__libc_calloc': 'calloc', '__libc_start_main': '__libc_start_main', '__mmap': 'mmap', '__srandom': 'srand', '_IO_puts': 'puts', 'strncpy': 'strncpy', '__libc_system': 'system', 'strtol': 'strtol', 'fputc': 'putc', '_IO_feof': 'feof', '_IO_fprintf': 'fprintf', 'strlen': 'strlen', '__mprotect': 'mprotect', 'putchar': 'putchar', 'getchar': 'getchar', 'exit': 'exit', '__libc_csu_init': '__libc_csu_init', 'rewind': 'rewind', '__ctype_b_loc': '__ctype_b_loc', '__libc_realloc': 'realloc', '__isoc99_sscanf': 'sscanf', '_IO_fseek': 'fseek', '__uname': 'uname', '__libc_lseek': 'lseek', '__getpid': 'getpid', '__libc_malloc': 'malloc', '__libc_close': 'close', 'time': 'time', '__libc_csu_fini': '__libc_csu_fini', '__ctype_toupper_loc': '__ctype_toupper_loc', '__libc_open': 'open', '_IO_fputs': 'fputs', '__libc_write': 'write', 'atoi': 'atoi', '_IO_vsprintf': 'sprintf', '__ctype_tolower_loc': '__ctype_tolower_loc', 'perror': 'perror', 'memcpy': 'memcpy', '__snprintf': 'snprintf', '_IO_fputc': 'fputc', '_IO_fgets': 'fgets', 'strstr': 'strstr', '_IO_getc': '_IO_getc', '_IO_new_fopen': 'fopen', '_IO_fread': 'fread', 'strchr': 'strchr', '__errno_location': '__errno_location', '_IO_fgetc': 'fgetc', 'strcpy': 'strcpy', '__brk': 'brk', '_IO_new_fclose': 'fclose', '_IO_ftell': 'ftell', 'strcmp': 'strcmp', '__libc_free': 'free'}
class StaticScan(object):
    def __init__(self,binary,signature_file,base_addr):
        self.binary=binary
        self.func_file=self.binary+'_func'
        self.signature_file=signature_file
        self.base_addr=base_addr
        self.dic = {
        #temp for special func
                 "printf":["5589E583EC0C8D450C894424088B450889442404",0],
                 "scanf" :["8975F8897DFC66833A0089D3783A8B7248658B3D",15]
                 }
        self.hooks=[]
        self.LIBC_NAME=['glibc','libc','linux_kernel']
        self.cache = self.run_lscan()
        print self.cache
        self.run()

    def run_lscan(self):
        return lscan.lscan(binfile=self.binary, sigfile=self.signature_file, debug=True)

    def handy_recognize(self):
        ret={}
        with open(self.binary, "rb") as f:
            c = f.read()
            f.close()
        for i in (self.dic):
            if c.find(self.dic[i][0].decode('hex')) != -1:
                ret[c.find(self.dic[i][0].decode('hex'))+self.base_addr-self.dic[i][1]]=i
        return ret

    def run(self):
        funcs = self.cache
        ret=self.handy_recognize()
        funcs.update(ret)
        maps = func_list
        for a,b in funcs.iteritems():
            for libc in self.LIBC_NAME:
                if b in angr.SIM_PROCEDURES[libc]:
                    item=(a,angr.SIM_PROCEDURES[libc][b])
                    self.hooks.append(item)
                    break
                if b in maps and maps[b] in angr.SIM_PROCEDURES[libc]:
                    item=(a,angr.SIM_PROCEDURES[libc][maps[b]])
                    self.hooks.append(item)
                    break
        return True

    def well_printf(self):
        dic = []
        for item in self.hooks:
            print hex(item[0]),",",item[1]
            dic.append([hex(item[0]),item[1]])
        return dic

def test():
    xx=StaticScan('cb','2333.sig',0x08048000)
    xx.well_printf()

def test2():
    #binary_arr=['b64_encode_1','Equation_Parser_bad_index','Equation_Parser_overflow','Equation_Parser_overflow_ROP','HTML_filter_INTOverflow_eip_1','HTML_filter_INTOverflow_eip_2','notes_DoubleFree','Read_Httpd_Log_1','YY_IO_BS_003_ROP','YY_IO_BS_005_eip']
    binary_arr=['/usr/downloads/test/testcase/robo_change/work/binary/_89_pwn09',]
    for binary in binary_arr:
        xx=StaticScan(binary,'2333.sig',0x08048000)
        print '------------------------****  ',binary,'  ****---------------------------'
        xx.well_printf()


if __name__ == '__main__':
    print "1"
    test2()