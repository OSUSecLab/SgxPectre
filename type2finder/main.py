#!/usr/bin/python

import os
import sys
import angr
from angr import SimProcedure
from capstone.x86_const import *

class G1(object):
	def __init__(self, start = None, end = None, rega = None, regb = None, regc = None):
		self.start = start
		self.end = end
		self.rega = rega
		self.regb = regb
		self.regc = regc

class G2(object):
	def __init__(self, start = None, end = None, rega = None, regb = None):
		self.start = start
		self.end = end
		self.rega = rega
		self.regb = regb



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
		self.interestedregs = [X86_REG_RAX, X86_REG_RBX, \
					X86_REG_RCX, X86_REG_RDX, \
					X86_REG_RDI, X86_REG_RSI, \
					X86_REG_R8, \
					X86_REG_R9, \
					X86_REG_R10, \
					X86_REG_R11, \
					X86_REG_R12, \
					X86_REG_R13, \
					X86_REG_R14, \
					X86_REG_R15,
					X86_REG_EAX, X86_REG_EBX, \
					X86_REG_ECX, X86_REG_EDX, \
					X86_REG_EDI, X86_REG_ESI, \
					X86_REG_R8D, \
					X86_REG_R9D, \
					X86_REG_R10D, \
					X86_REG_R11D, \
					X86_REG_R12D, \
					X86_REG_R13D, \
					X86_REG_R14D, \
					X86_REG_R15D]
		self.uncontrollableregs = [X86_REG_RAX, X86_REG_RCX, \
					X86_REG_EAX, X86_REG_ECX]
		self.startinsns = []
		self.firstregs = []
		self.secondregs = []
		self.thirdregs = []
		self.fourthregs = []
		self.gflags = []
		self.insnss = []
		self.leakinsnind = []
		self.g1 = []
		self.g2 = []


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
		
		
global info
info = Info()



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

def disassemble():
	global asmfile
	info.asmfile = sys.argv[1] + "_asm"
	comm = "objdump -S " + sys.argv[1] + " > " + info.asmfile
	#os.system(comm)

def findfirstins():
	funcflag = 0
	f1 = open(info.asmfile,'r')
	lines1 = f1.readlines()
	for line1 in lines1:
		if funcflag == 1 and ":" in line1:
			addr = parseinsaddr(line1, ":")
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


	#for csinsn in info.insns:
	#	print hex(csinsn.address)
	#	print csinsn.mnemonic
	#	print csinsn.op_str
	#	print csinsn.size







def preprocessing():
	disassemble()
	findinsaddr()
	capstoneparse()


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








def findgadget():
	# step 1: find mov MEM, reg instruction
	for csinsn in info.insns:
		if csinsn.id != X86_INS_LEA:
			if len(csinsn.operands) >= 2:

				if csinsn.mnemonic.startswith("mov") \
					 and csinsn.operands[0].type == X86_OP_REG \
					 and csinsn.operands[0].value.reg in info.interestedregs \
					 and csinsn.operands[1].type == X86_OP_MEM:

					if ((csinsn.operands[1].value.mem.base != 0 \
						 and csinsn.operands[1].value.mem.base in info.interestedregs \
						 and not csinsn.operands[1].value.mem.base in info.uncontrollableregs \
						 and csinsn.operands[1].value.mem.index == 0) \
						 or (csinsn.operands[1].value.mem.base == 0 \
						 and csinsn.operands[1].value.mem.index != 0 \
						 and csinsn.operands[1].value.mem.index in info.interestedregs
						 and not csinsn.operands[1].value.mem.index in info.uncontrollableregs)):

							#print hex(csinsn.address)
							#print csinsn.operands[1].type # would like the one of MEM, 3
							#print csinsn.operands[0].type # would like the one of REG, 1

							info.startinsns.append(csinsn)

							if csinsn.operands[1].value.mem.base != 0:
								info.firstregs.append(csinsn.operands[1].value.mem.base)
								#print csinsn.reg_name(csinsn.operands[1].value.mem.base)
							if csinsn.operands[1].value.mem.index != 0:
								info.firstregs.append(csinsn.operands[1].value.mem.index)
								#print csinsn.reg_name(csinsn.operands[1].value.mem.index)

							info.secondregs.append(csinsn.operands[0].value.reg)
							info.thirdregs.append(0)
							info.fourthregs.append(0)
							info.gflags.append(-1)
							info.leakinsnind.append(-1)

	#for si in info.startinsns:
	#	print hex(si.address)



	# step 2: do symbolic execution from each such potential beginning instruction
	for startinsn in info.startinsns:
		# get index, reg1, reg2
		ind = info.startinsns.index(startinsn)
		print "checking %dth of %d potential gadget (%.2f%% complete):" % (ind, len(info.startinsns), float(ind)/float(len(info.startinsns)) *100)
		print "at address: %s" % hex(startinsn.address)
		reg1 = info.firstregs[ind]
		reg2 = info.secondregs[ind]
		reg3 = None
		leareg = 0
		learegstr = None
		#print reg1
		#print reg2

		#init rax, rbx, rcx... r15
		info.state = info.b.factory.entry_state(addr=startinsn.address, add_options={angr.options.CONSTRAINT_TRACKING_IN_SOLVER})
		

		#print hex(info.state.addr)

		# rax and rcx is not controllable since EENTER changes its value
		initregs = []
		for reg in ["rbx","rdx","rdi","rsi","r8","r9","r10","r11","r12","r13","r14","r15"]:
			vreg = info.state.se.BVS("init_" + reg, 64)
			initregs.append(vreg)
			info.state.registers.store(reg, vreg)


		#for ir in initregs:
		#	print ir

		# init reg1 and reg2
		vreg1 = info.state.se.BVS("init_vreg1_" + startinsn.reg_name(reg1), 64)
		vreg2 = info.state.se.BVS("init_vreg2_" + startinsn.reg_name(reg2), 64)

		#print list(vreg1.variables)[0]
		#print list(vreg2.variables)[0]



		#print vreg1
		#print vreg2

		insnmap = {"eax":"rax","ebx":"rbx","ecx":"rcx","edx":"rdx","edi":"rdi","esi":"rsi",
				"r8d":"r8","r9d":"r9","r10d":"r10","r11d":"r11","r12d":"r12","r13d":"r13",
				"r14d":"r14","r15d":"r15"}
		#print insnmap["eax"]
		#print "eax" in insnmap
		#print "rax" in insnmap

		if str(startinsn.reg_name(reg1)) in insnmap:
			info.state.registers.store(insnmap[str(startinsn.reg_name(reg1))], vreg1)
			#print info.state.registers.load(insnmap[str(startinsn.reg_name(reg1))])
		else:
			info.state.registers.store(str(startinsn.reg_name(reg1)), vreg1)
			#print info.state.registers.load(str(startinsn.reg_name(reg1)))

		if str(startinsn.reg_name(reg2)) in insnmap:
			info.state.registers.store(insnmap[str(startinsn.reg_name(reg2))], vreg2)
			#print info.state.registers.load(insnmap[str(startinsn.reg_name(reg2))])
		else:
			info.state.registers.store(str(startinsn.reg_name(reg2)), vreg2)
			#print info.state.registers.load(str(startinsn.reg_name(reg2)))


		# start SE
		info.states = []
		info.states.append(info.state)

		instno = 0
		leaflag = 0
		findflag = 0
		leainitflag = 0
		#print "***"
		while True:
			# if nothing left in worklist, break
			if not info.states:
				break
			#print len(info.states)

			# pop one state for symbolic execution
			info.state = info.states.pop(0)


			#
			# check the new state
			#

			# if this path is unsatisfiable, continue
			if info.state.se.satisfiable() == False:
				continue

			# if return to top function, stop doing this work, continue

			if info.state.regs.rip.symbolic:
				continue
			if info.state.addr == 0:
				print "return to top function"
				print "continue"
				print hex(info.state.addr)
				continue


			if instno == 1:
				if str(startinsn.reg_name(reg1)) in insnmap:
					info.state.registers.store(insnmap[str(startinsn.reg_name(reg1))], vreg1)
					#print info.state.registers.load(insnmap[str(startinsn.reg_name(reg1))])
				else:
					info.state.registers.store(str(startinsn.reg_name(reg1)), vreg1)
					#print info.state.registers.load(str(startinsn.reg_name(reg1)))

				if str(startinsn.reg_name(reg2)) in insnmap:
					info.state.registers.store(insnmap[str(startinsn.reg_name(reg2))], vreg2)
					#print info.state.registers.load(insnmap[str(startinsn.reg_name(reg2))])
				else:
					info.state.registers.store(str(startinsn.reg_name(reg2)), vreg2)
					#print info.state.registers.load(str(startinsn.reg_name(reg2)))

			if leaflag == 1 and leainitflag == 0:
				leainitflag = 1
				vleareg = info.state.se.BVS("init_leareg", 64)
				if learegstr in insnmap:
					info.state.registers.store(insnmap[learegstr], vleareg)
				else:
					info.state.registers.store(learegstr, vleareg)
				#print "set lea reg"
				#print learegstr
				#print info.state.registers.load(learegstr)
				


			#print hex(info.state.addr)


			
			hazardousins = [X86_INS_JAE,X86_INS_JA,X86_INS_JBE,X86_INS_JB,X86_INS_JCXZ,X86_INS_JECXZ,X86_INS_JE,X86_INS_JGE,X86_INS_JG,
						X86_INS_JLE,X86_INS_JL,X86_INS_JMP,X86_INS_JNE,X86_INS_JNO,X86_INS_JNP,X86_INS_JNS,X86_INS_JO,
						X86_INS_JP,X86_INS_JRCXZ,X86_INS_JS, X86_INS_LJMP, X86_INS_CALL, X86_INS_LCALL, X86_INS_RET, 
						X86_INS_IRET, X86_INS_IRETD, X86_INS_IRETQ, X86_INS_RETF, X86_INS_RETFQ]

			#print info.insnsmap[info.state.addr]
			#print info.insns.index(info.insnsmap[info.state.addr])
			currentinsn = info.insnsmap[info.state.addr]



			if instno != 0:
				if len(currentinsn.operands) == 2:
					op = currentinsn.operands[1]
					if op.type == X86_OP_MEM:
						if op.value.mem.base != 0 and op.value.mem.index != 0:
							#print str(startinsn.reg_name(op.value.mem.base))
							#print info.state.registers.load(str(startinsn.reg_name(op.value.mem.base)))
							#print str(startinsn.reg_name(op.value.mem.index))
							#print info.state.registers.load(str(startinsn.reg_name(op.value.mem.index)))
							#print info.state.registers.load(str(startinsn.reg_name(op.value.mem.base))).variables
							#print info.state.registers.load(str(startinsn.reg_name(op.value.mem.index))).variables
							if list(vreg2.variables)[0] in info.state.registers.load(str(startinsn.reg_name(op.value.mem.base))).variables or \
								list(vreg2.variables)[0] in info.state.registers.load(str(startinsn.reg_name(op.value.mem.index))).variables:
									# normal case
									if currentinsn.id != X86_INS_LEA:
										if list(vreg2.variables)[0] in info.state.registers.load(str(startinsn.reg_name(op.value.mem.base))).variables:
											# check index
											for ir in initregs:
												if list(ir.variables)[0] in info.state.registers.load(str(startinsn.reg_name(op.value.mem.index))).variables:
													#found
													findflag = 1
													info.g1.append(G1(startinsn.address, currentinsn.address, reg1, reg2, op.value.mem.index))
													continue



										if list(vreg2.variables)[0] in info.state.registers.load(str(startinsn.reg_name(op.value.mem.index))).variables:
											# check base
											for ir in initregs:
												if list(ir.variables)[0] in info.state.registers.load(str(startinsn.reg_name(op.value.mem.base))).variables:
													#found
													findflag = 1
													info.g1.append(G1(startinsn.address, currentinsn.address, reg1, reg2, op.value.mem.base))
													continue

									# lea case
									else:
										if list(vreg2.variables)[0] in info.state.registers.load(str(startinsn.reg_name(op.value.mem.base))).variables:
											# check index
											for ir in initregs:
												if list(ir.variables)[0] in info.state.registers.load(str(startinsn.reg_name(op.value.mem.index))).variables:
													# look forward and find indirect memory access
													leaflag = 1
													leareg = currentinsn.operands[0].value.reg
													learegstr = str(startinsn.reg_name(leareg))
													reg3 = op.value.mem.index
													#print "leareg"
													#print leareg
													continue



										if list(vreg2.variables)[0] in info.state.registers.load(str(startinsn.reg_name(op.value.mem.index))).variables:
											# check base
											for ir in initregs:
												if list(ir.variables)[0] in info.state.registers.load(str(startinsn.reg_name(op.value.mem.base))).variables:
													leaflag = 1
													leareg = currentinsn.operands[0].value.reg
													learegstr = str(startinsn.reg_name(leareg))
													reg3 = op.value.mem.base
													#print "leareg"
													#print leareg
													continue


				for op in currentinsn.operands:
					if op.type == X86_OP_MEM:
						if op.value.mem.base != 0 and op.value.mem.index == 0:
							#lea case
							if leaflag == 1:
								if currentinsn.id != X86_INS_LEA:
									#print info.state.registers.load(str(startinsn.reg_name(op.value.mem.base))).variables
									if list(vleareg.variables)[0] in info.state.registers.load(str(startinsn.reg_name(op.value.mem.base))).variables:
										findflag = 1
										info.g1.append(G1(startinsn.address, currentinsn.address, reg1, reg2, reg3))
										continue
							# [regA, regB] case
							if currentinsn.id != X86_INS_LEA:
								if list(vreg2.variables)[0] in info.state.registers.load(str(startinsn.reg_name(op.value.mem.base))).variables:
									#print "[regA, regB]"
									#print hex(currentinsn.address)
									findflag = 2
									info.g2.append(G2(startinsn.address, currentinsn.address, reg1, reg2))
									continue

							

			# current instruction should not be jump/call/ret, memfence or any other hazardous instruction, stop doing this work, continue
			if currentinsn.id in hazardousins:
				#print "hazardous"
				#print currentinsn.id
				continue



			#
			# get successor(s)
			#
			try:
				info.succs = info.b.factory.successors(info.state, num_inst=1).successors
			except:
				continue

			#info.succs = info.b.factory.successors(info.state, num_inst=1).successors

			#print "len of succs:"
			#print len(succs)

			#
			# check the successor(s)
			#

			# number of successors should be exactly one
			if len(info.succs) != 1:
				continue

			# successor should be exactly next instruction
			#print hex(info.succs[0].addr)
			if info.insns.index(currentinsn) + 1 < len(info.insns):
				#print hex(info.insns[info.insns.index(csinsn) + 1].address)
				if info.insns[info.insns.index(currentinsn) + 1].address != info.succs[0].addr:
					continue


			# successor should be within 10 instructions of start instruction
			if info.insns.index(currentinsn) + 1 > info.insns.index(startinsn) + 9:
				continue

			# now the control flow of successor seems right, we check the successor

			instno = instno + 1
			info.states.extend(info.succs)

	print "*********************************"
	print "*********************************"
	print "*********************************"
	print "*************RESULTS:************"
	print "*********************************"
	print "*********************************"
	print "*********************************"
	print "*********************************"
	print "[regA, regB, regC] gadgets:"
	print "*********************************"
	for ga in info.g1:
		print "Gadget %d:" % info.g1.index(ga)
		print "start address: %x" % ga.start
		print "end address: %x" % ga.end
		print "regA: %s" % str(startinsn.reg_name(ga.rega))
		print "regB: %s" % str(startinsn.reg_name(ga.regb))
		print "regC: %s" % str(startinsn.reg_name(ga.regc))
	print "*********************************"
	print "*********************************"
	print "*********************************"
	print "[regA, regB] gadgets:"
	print "*********************************"
	for ga in info.g2:
		print "Gadget %d:" % info.g2.index(ga)
		print "start address: %x" % ga.start
		print "end address: %x" % ga.end
		print "regA: %s" % str(startinsn.reg_name(ga.rega))
		print "regB: %s" % str(startinsn.reg_name(ga.regb))




#
# param1: binary to load. Shared library .so file or executable.
# param2: function api address in binary.
#
def main():
	# parameter handling
	print "parameters:"
	for arg in sys.argv[1:]:
		print arg
	if len(sys.argv) != 2:
		print "ERROR: accept exactly 1 parameters."
		print "param1: binary to load. Shared library .so file or executable."
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
