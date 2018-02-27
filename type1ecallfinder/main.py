#!/usr/bin/python

import os
import sys
import angr
from angr import SimProcedure
from capstone.x86_const import *
import time

class G(object):
	def __init__(self, addr = None, gtype = None, regsaffected = None, regs = None):
		self.addr = addr
		# 1 for jump
		# 2 for call
		# 3 for return
		self.gtype = gtype
		self.regsaffected = regsaffected
		# a list of registers' values, symbolic or concrete
		self.regs = regs




class Info(object):
	def __init__(self):
		self.picflag = None
		self.b = None
		self.asmfile = None
		self.code = None
		self.insns = []
		self.insnsmap = {}
		self.insnaddrs = []
		self.codeoffset = None

		self.xsavelist = []
		self.xsaveclist = []
		self.xsaveslist = []
		self.xsave64list = []
		self.xsavec64list = []
		self.xsaves64list = []
		self.fxsavelist = []
		self.fxsave64list = []
		self.xrstorlist = []
		self.xrstorslist = []
		self.xrstor64list = []
		self.xrstors64list = []
		self.fxrstorlist = []
		self.fxrstor64list = []

		self.repstoslist = []

		self.rdrandlist = []

		self.enclulist = []
		self.enclaveentry = None

		self.state = None
		self.emptystate = None
		self.states = []
		self.targets1 = []
		self.targets2 = []
		self.succs = []

		self.encluflag = 0

		self.test = 0

		self.g = []
		self.interestedregs = ["rax","rbx","rcx","rdx","rdi","rsi","r8","r9","r10","r11","r12","r13","r14","r15"]
		self.controllableregs = ["rbx","rdx","rdi","rsi","r8","r9","r10","r11","r12","r13","r14","r15"]
		self.tstart = 0
		self.tend = 0
		
global info
info = Info()













def getinsaddr(line, separator):
	temp = line[:line.find(separator)]
	temp1 = int(temp, 16)
	if info.picflag == 1:
		temp2 = temp1 + 0x400000
	else:
		temp2 = temp1
	return temp2

def findenclu():
	f1 = open(info.asmfile,'r')
	lines1 = f1.readlines()
	for line1 in lines1:
		if "enclu" in line1:
			addr = getinsaddr(line1, ":")
			info.enclulist.append(addr)
			#print hex(addr)
	f1.close()
	

def findenclaveentry():
	f1 = open(info.asmfile,'r')
	lines1 = f1.readlines()
	for line1 in lines1:
		if "<enclave_entry>:" in line1:
			info.enclaveentry = getinsaddr(line1, "<")
			break
	f1.close()


def findaddresses():
	findenclu()
	findenclaveentry()


#
# search disassembly for unsupported instructions
#
# unsupported instructions:
# xsave
# xsavec
# xsaves
# xsave64
# xsavec64
# xsaves64
# fxsave
# fxsave64
# xrstor
# xrstors
# xrstor64
# xrstors64
# fxrstor
# fxrstor64
#
# rep stos
#
def findunsupportedinstructions():
	f1 = open(info.asmfile,'r')
	lines1 = f1.readlines()
	for line1 in lines1:
		if "\txsave " in line1:
			addr = getinsaddr(line1, ":")
			info.xsavelist.append(addr)
		if "\txsavec " in line1:
			addr = getinsaddr(line1, ":")
			info.xsaveclist.append(addr)
		if "\txsaves " in line1:
			addr = getinsaddr(line1, ":")
			info.xsaveslist.append(addr)
		if "\txsave64 " in line1:
			addr = getinsaddr(line1, ":")
			info.xsave64list.append(addr)
		if "\txsavec64 " in line1:
			addr = getinsaddr(line1, ":")
			info.xsavec64list.append(addr)
		if "\txsaves64 " in line1:
			addr = getinsaddr(line1, ":")
			info.xsaves64list.append(addr)
		if "\tfxsave " in line1:
			addr = getinsaddr(line1, ":")
			info.fxsavelist.append(addr)
		if "\tfxsave64 " in line1:
			addr = getinsaddr(line1, ":")
			info.fxsave64list.append(addr)
		if "\txrstor " in line1:
			addr = getinsaddr(line1, ":")
			info.xrstorlist.append(addr)
		if "\txrstors " in line1:
			addr = getinsaddr(line1, ":")
			info.xrstorslist.append(addr)
		if "\txrstor64 " in line1:
			addr = getinsaddr(line1, ":")
			info.xrstor64list.append(addr)
		if "\txrstors64 " in line1:
			addr = getinsaddr(line1, ":")
			info.xrstors64list.append(addr)
		if "\tfxrstor " in line1:
			addr = getinsaddr(line1, ":")
			info.fxrstorlist.append(addr)
		if "\tfxrstor64 " in line1:
			addr = getinsaddr(line1, ":")
			info.fxrstor64list.append(addr)

		#
		# TBD: rep, stos
		#
		if "\trep stos " in line1:
			addr = getinsaddr(line1, ":")
			info.repstoslist.append(addr)

		if "\trdrand " in line1 and not "<" in line1:
			addr = getinsaddr(line1, ":")
			info.rdrandlist.append(addr)


	f1.close()




#
# the diassembly file is named with original_file_name_asm in the same dir
#
def disassemble():
	global asmfile
	info.asmfile = sys.argv[1] + "_asm"
	comm = "objdump -S " + sys.argv[1] + " > " + info.asmfile
	#os.system(comm)

def passf(state):
	pass

def ocallocf():
	return 0

class Ocalloc(SimProcedure):
	def run(self):
		return 1

class GetEnclaveState(SimProcedure):
	def run(self):
		info.state.regs.rax = 2
		return 2

def firstcallf(state):
	state.regs.eax = 0

def ecallnrf(state):
	state.regs.eflags = 1

def policyf(state):
	state.regs.rax = 0

def privatebitef(state):
	state.regs.eflags = 0xffffffffffffffff

def threadpolicyf(state):
	state.regs.rdx = 0

def randf(state):
	state.regs.rax = 0


class WithinEnclave(SimProcedure):
	def run(self):
		info.state.regs.rax = 1
		return 1


def handleaddresses():
	for addr in info.xsavelist:
		info.b.hook(addr, passf, length=3)
	for addr in info.xsaveclist:
		info.b.hook(addr, passf, length=3)
	for addr in info.xsaveslist:
		info.b.hook(addr, passf, length=3)
	for addr in info.xsave64list:
		info.b.hook(addr, passf, length=4)
	for addr in info.xsavec64list:
		info.b.hook(addr, passf, length=4)
	for addr in info.xsaves64list:
		info.b.hook(addr, passf, length=4)
	for addr in info.fxsavelist:
		info.b.hook(addr, passf, length=3)
	for addr in info.fxsave64list:
		info.b.hook(addr, passf, length=4)
	for addr in info.xrstorlist:
		info.b.hook(addr, passf, length=4)
	for addr in info.xrstorslist:
		info.b.hook(addr, passf, length=4)
	for addr in info.xrstor64list:
		info.b.hook(addr, passf, length=4)
	for addr in info.xrstors64list:
		info.b.hook(addr, passf, length=4)
	for addr in info.fxrstorlist:
		info.b.hook(addr, passf, length=4)
	for addr in info.fxrstor64list:
		info.b.hook(addr, passf, length=4)
	for addr in info.repstoslist:
		info.b.hook(addr, passf, length=2)

	# TBD: rdrand
	for addr in info.rdrandlist:
		info.b.hook(addr, passf, length=3)


	# sgx_ocalloc
	info.b.hook_symbol("sgx_ocalloc", Ocalloc())

	# get_enclave_state quick fix
	# TBD
	info.b.hook_symbol("get_enclave_state", GetEnclaveState())

	info.b.hook_symbol("sgx_is_within_enclave", WithinEnclave())



	
	# sgx sdk
	info.b.hook(0x402c5c, firstcallf, length = 7)
	info.b.hook(0x402c72, ecallnrf, length = 4)
	info.b.hook(0x402c8f, policyf, length = 4)
	info.b.hook(0x402d02, privatebitef, length = 6)
	info.b.hook(0x40321f, threadpolicyf, length = 4)


	#
	# graphene
	#
	info.b.hook(0x1528d, passf, length = 5)

	#
	# rust
	#
	info.b.hook(0x405192, randf, length = 5)
	info.b.hook(0x404a02, passf, length = 5)
	info.b.hook(0x404bac, firstcallf, length = 7)


def parseinsaddr(line, separator):
	temp = line[:line.find(separator)]
	try:
		temp1 = int(temp, 16)
	except:
		return -1


	if info.picflag == 1:
		temp2 = temp1 + 0x400000
	else:
		temp2 = temp1
	return temp2


def findfirstins():
	funcflag = 0
	f1 = open(info.asmfile,'r')
	lines1 = f1.readlines()
	for line1 in lines1:
		if funcflag == 1 and ":" in line1:
			addr = getinsaddr(line1, ":")
			#print line1
			#print hex(addr)
			info.codeoffset = addr
			break
		if ">:" in line1:
			funcflag = 1
	f1.close()

def findinsaddr():
	f1 = open(info.asmfile,'r')
	lines1 = f1.readlines()
	for line1 in lines1:
		if ":" in line1:
			addr = parseinsaddr(line1, ":")
			if addr == -1:
				continue
			info.insnaddrs.append(addr)

	f1.close()


	#for ad in info.insnaddrs:
	#	print hex(ad)



def findnextinsaddr(addr):
	# beginning
	if addr == -1:
		if info.insnaddrs:
			return info.insnaddrs[0]
		else:
			return -2


	# no more instruction
	if addr >= info.insnaddrs[-1]:
		return -1

	try:
		oldindex = info.insnaddrs.index(addr)
		newindex = oldindex + 1
		ad = info.insnaddrs[newindex]
		#print "oldindex: %d" % oldindex
		#print "newindex: %d" % newindex
		#print "new ins addr: %x" % ad

		return ad

	except:
		return -3

def capstoneparse():
	start = -1
	while True:
		addr = findnextinsaddr(start)
		if addr < 0:
			break
		#print hex(addr)
		with open(sys.argv[1], 'rb') as f:
			if info.picflag == 1:
				seekstart = addr - 0x400000
			else:
				seekstart = addr

			f.seek(seekstart, 1)
			info.code = f.read()
			insns = info.b.arch.capstone.disasm(info.code, addr)
			insnlist = list(insns)
			info.insns.extend(insnlist)
			for ins in insnlist:
				info.insnsmap[ins.address] = ins

		f.close()

		if insnlist:
			start = insnlist[-1].address
		else:
			start = addr

	#print "capstone:"
	#for ins in info.insns:
	#	print hex(ins.address)





def preprocessing():
	disassemble()
	findinsaddr()
	capstoneparse()
	findunsupportedinstructions()
	findaddresses()
	handleaddresses()


#
# param1: binary to load. Shared library .so file or executable.
#
def load_binary():
	if sys.argv[1].endswith(".so"):
		info.picflag = 1
	try:
		info.b = angr.Project(sys.argv[1],load_options={'auto_load_libs': False})
	except:
		info.picflag = 0
		info.b = angr.Project(sys.argv[1], 
			main_opts = {'backend': 'blob', 'custom_arch': 'amd64'},
			load_options={'auto_load_libs': False})

def printresults():
	gendinslist = []
	resultindex = 0

	info.tend = time.time()
	print "*********************************"
	print "*********************************"
	print "*********************************"
	print "*************RESULTS:************"
	print "*********************************"
	print "*********************************"
	print "*********************************"
	print "*********************************"
	print "*************gadgets:************"
	print "*********************************"
	for g1 in info.g:
		if not g1.addr in gendinslist:
			gendinslist.append(g1.addr)
			print "*********************************"
			print "gadget %d:" % resultindex
			print "*********************************"
			print "address:"
			print hex(g1.addr)
			print "gtype:"
			print g1.gtype
			print "regs affected:"
			for g2 in g1.regsaffected:
				print g2
			print "regs:"
			for g2 in g1.regs:
				print g2
			resultindex = resultindex + 1
	print "*********************************"
	print "*********************************"
	print "%f seconds." % (info.tend-info.tstart)
	print "*********************************"
	print "*********************************"


def makeregistersymbolic(s):
	info.state.regs.rax = info.state.se.BVS(s + "rax", 64)
	info.state.regs.rbx = info.state.se.BVS(s + "rbx", 64)
	info.state.regs.rcx = info.state.se.BVS(s + "rcx", 64)
	info.state.regs.rdx = info.state.se.BVS(s + "rdx", 64)
	info.state.regs.rdi = info.state.se.BVS(s + "rdi", 64)
	info.state.regs.rsi = info.state.se.BVS(s + "rsi", 64)
	info.state.regs.r8 = info.state.se.BVS(s + "r8", 64)
	info.state.regs.r9 = info.state.se.BVS(s + "r9", 64)
	info.state.regs.r10 = info.state.se.BVS(s + "r10", 64)
	info.state.regs.r11 = info.state.se.BVS(s + "r11", 64)
	info.state.regs.r12 = info.state.se.BVS(s + "r12", 64)
	info.state.regs.r13 = info.state.se.BVS(s + "r13", 64)
	info.state.regs.r14 = info.state.se.BVS(s + "r14", 64)
	info.state.regs.r15 = info.state.se.BVS(s + "r15", 64)



def findgadget():
	info.tstart = time.time()
	# original state and worklist
	info.state = info.b.factory.entry_state(addr=int(sys.argv[2], 16), add_options={angr.options.CONSTRAINT_TRACKING_IN_SOLVER})
	info.emptystate = info.b.factory.entry_state(addr=int(sys.argv[2], 16), add_options={angr.options.CONSTRAINT_TRACKING_IN_SOLVER})
	# make rax,rbx,rcx,rdx,rsi,rdi,r8,r9,r10,r11,r12,r13,r14,r15 symbolic
	makeregistersymbolic("init_")
	info.state.regs.rsp = initial_rsp = info.state.se.BVS("rsp", 64)
	info.state.regs.rbp = info.state.se.BVS("rbp", 64)
	info.state.regs.rax = 0
	info.state.regs.edi = 0
	info.state.regs.gs = 0x7f000000
	info.state.mem[info.state.regs.gs].uint64_t = 0x7f000000
	#info.state.mem[info.state.regs.gs + 0x8].uint64_t = 0x7e000000
	#info.state.mem[info.state.regs.gs + 0x10].uint64_t = 0x7e000000
	info.state.mem[info.state.regs.gs +0x38].uint64_t = 0x100


	info.states.append(info.state)

	# set state
	#info.state.regs.rdi = 0x1000
	#info.state.mem[info.state.regs.rdi].uint64_t = 12

	#sysbolic execution
	while True:
		# if nothing left in worklist
		# break
		if not info.states:
			break
		print len(info.states)

		# pop one state for symbolic execution
		info.state = info.states.pop(0)


		#
		# check the new state
		#

		# if this path is unsatisfiable
		# continue
		if info.state.se.satisfiable() == False:
			continue

		# if return to top function
		# stop doing this work
		# continue
		if info.state.addr == 0:
			print "return to top function"
			print "continue"
			print hex(info.state.addr)
			continue


		#empty = info.emptystate.copy()
		#print "empty:"
		#print empty.se.constraints
		#empty.se.add(info.state.regs.rsp == initial_rsp)
		#print empty.satisfiable()



		print hex(info.state.addr)

		'''
		#print hex(info.state.scratch.bbl_addr)
		#print info.state.scratch.irsb
		#print info.state.se.constraints
		print info.state.regs.rsp
		print info.state.regs.rbp
		print info.state.mem[initial_rsp + 0xffffffffffffffd0].uint64_t
		print info.state.callstack
		#print hex(info.state.mem[info.state.regs.rsp].uint64_t.concrete)
		print info.state.regs.gs
		print info.state.regs.rax
		print info.state.mem[info.state.regs.rax + 0x8].uint64_t
		#print info.state.regs.rdi
		#print info.state.mem[info.state.regs.rax +0x8].uint64_t
		print info.state.regs.rbp
		print info.state.mem[initial_rsp - 0x30].uint64_t
		'''
		#print info.state.regs.rax









		if len(info.insnsmap[info.state.addr].operands) == 1 and info.insnsmap[info.state.addr].operands[0].type == X86_OP_REG:

			# found a indirect jump gadget
			if info.insnsmap[info.state.addr].id == X86_INS_LJMP or info.insnsmap[info.state.addr].id == X86_INS_JMP:
				print hex(info.state.addr)

				gtype = 1
				regsaffected = []
				# each current reg value				
				for reg in info.interestedregs:
					# each init_rxx
					for reg1 in info.controllableregs:
						for v in list(info.state.registers.load(reg).variables):
							if v.startswith("init_" + reg1):
								regsaffected.append(reg)

				regs = []
				# get current regs values
				for reg in info.interestedregs:
					regs.append(info.state.registers.load(reg))

				info.g.append(G(info.state.addr, gtype, regsaffected, regs))


				printresults()
				exit()


			# found a indirect call gadget
			if info.insnsmap[info.state.addr].id == X86_INS_CALL or info.insnsmap[info.state.addr].id == X86_INS_LCALL:
				print hex(info.state.addr)

				gtype = 2
				regsaffected = []
				# each current reg value				
				for reg in info.interestedregs:
					# each init_rxx
					for reg1 in info.controllableregs:
						for v in list(info.state.registers.load(reg).variables):
							if v.startswith("init_" + reg1):
								regsaffected.append(reg)

				regs = []
				# get current regs values
				for reg in info.interestedregs:
					regs.append(info.state.registers.load(reg))

				info.g.append(G(info.state.addr, gtype, regsaffected, regs))


				printresults()
				exit()

		# a potential return gadget
		if info.insnsmap[info.state.addr].id == X86_INS_RET or info.insnsmap[info.state.addr].id == X86_INS_IRET \
			or info.insnsmap[info.state.addr].id == X86_INS_IRETD or info.insnsmap[info.state.addr].id == X86_INS_IRETQ \
			or info.insnsmap[info.state.addr].id == X86_INS_RETF or info.insnsmap[info.state.addr].id == X86_INS_RETFQ:



			print hex(info.state.addr)

			gtype = 3
			regsaffected = []
			# each current reg value				
			for reg in info.interestedregs:
				# each init_rxx
				for reg1 in info.controllableregs:
					for v in list(info.state.registers.load(reg).variables):
						if v.startswith("init_" + reg1):
							regsaffected.append(reg)

			#print "length of regsaffected:"
			#print len(regsaffected)

			# found a return gadget
			if len(regsaffected) >=3:

				regs = []
				# get current regs values
				for reg in info.interestedregs:
					regs.append(info.state.registers.load(reg))

				info.g.append(G(info.state.addr, gtype, regsaffected, regs))

				'''
				for g1 in info.g:
					print "gadget %d:" % info.g.index(g1)
					print "address:"
					print hex(g1.addr)
					print "gtype:"
					print g1.gtype
					print "regs affected:"
					for g2 in g1.regsaffected:
						print g2
					print "regs:"
					for g2 in g1.regs:
						print g2
				'''


			else:
				continue

		#print "len(info.g): %s" % len(info.g)
		if len(info.g) >= 20 and info.picflag == 0:
			printresults()
			exit()






		# error handling path
		if info.state.addr == 0x403480:
			print "stop at 0x403480"
			continue

		# error handling path
		if info.state.addr == 0x4053d0:
			print "stop at 0x4053d0"
			continue


		# abort path
		if info.state.addr == 0x404c6b:
			print "stop at 0x404c6b"
			continue

		# abort path
		if info.state.addr == 0x4068b8:
			print "stop at 0x4068b8"
			continue





		# check if this instruction is enclu
		if info.state.addr in info.enclulist:
			info.encluflag = 1
		if info.encluflag == 1:
			print "info.encluflag == 1"


		#
		# get state successors
		# moving forwards
		#
		info.succs = []

		# if not enclu instruction
		if info.encluflag == 0:
			#for suc in info.b.factory.successors(info.state, num_inst=1).successors:
			#	if suc.addr > info.state.addr:
			#		info.succs.append(suc)
			info.succs = info.b.factory.successors(info.state, num_inst=1).successors

			if len(info.succs) >= 2:
				print "successors >= 2"
				#for su in info.succs:
				#	if su.addr < info.state.addr:
				#		print "potential loop"
				#		exit()

		# if enclu instruction
		else:
			info.encluflag = 0
			# set rip register
			info.state.regs.rip = info.enclaveentry

			# make rax,rbx,rcx,rdx,rsi,rdi,r8,r9,r10,r11,r12,r13,r14,r15 symbolic
			makeregistersymbolic("exit_");
			info.state.regs.rax = 0
			info.state.regs.edi = -2


			info.succs = [info.state]
			print "EEXIT"
			continue




		#
		# check successors
		#
		continueflag = 0
		if info.b.factory.successors(info.state, num_inst=1).unconstrained_successors:
			for succ in info.b.factory.successors(info.state, num_inst=1).unconstrained_successors:
				empty = info.emptystate.copy()
				# stack empty
				# normal exit
				if empty.se.satisfiable([succ.regs.rsp <= initial_rsp + 0x8]):
					print "normal exit"
					print "exit address:"
					print hex(info.state.addr)
					continueflag = 1


				# indirect jump/call/return
				else:
					print "indirect jump/call/return"
					print "intruction address:"
					print hex(info.state.addr)
					continueflag = 1

		#if info.state.addr == 0x404c88:
		#	print "stop at 0x404c88"
		#	print len(info.b.factory.successors(info.state, num_inst=1).successors)
		#	print hex(su.addr)
		#	print len(info.b.factory.successors(info.state, num_inst=1).unconstrained_successors)
		#	exit()

		if continueflag:
			continueflag = 0
			continue


		#
		# entend worklist
		#
		info.states.extend(info.succs)


#
# param1: binary to load. Shared library .so file or executable.
# param2: function api address in binary.
#
def main():
	# parameter handling
	print "parameters:"
	for arg in sys.argv[1:]:
		print arg
	if len(sys.argv) != 3:
		print "ERROR: accept exactly 2 parameters."
		print "param1: binary to load. Shared library .so file or executable."
		print "param2: function api address in binary."
		exit()

	#load binary
	load_binary()

	#preprocessing
	preprocessing()

	#find gadget
	findgadget()



#
#main function
#
if __name__ == "__main__":
	main()
