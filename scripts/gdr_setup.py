#!/usr/bin/python
import os,platform,subprocess,threading,time,sys
import commands
from threading import Thread
import math
import shutil
import cStringIO,operator
from optparse import OptionParser, SUPPRESS_HELP, OptionGroup
from subprocess import Popen, PIPE
import re

handler = open("gdr_install.log","w")
unhandler = open("gdr_uninstall.log","w")
fail_ban = ""
BLUE = '\033[1;34m'
GREEN = '\033[0;32m'
FAIL = '\033[91m'
RESET = '\033[0m'
pwd = os.getcwd()
supported_kver = ['4.14']
repomgr = ""
dist = ""
DISTRO = ""
ARCH = "x86_64"

OMPI_VERSION   = "3.1.2"
OSU_MB_VERSION = "5.0"
NVIDIA_VERSION = "410.72"

srcdir = pwd + os.sep + "src"
toolsdir = pwd + os.sep + "tools" + os.sep + "gdr_tools"
cuda_inc = ""
cuda_libpkg = ""
nvidiasrc = None


def install_targets(mods):
	global pwd
	global srcdir
	global toolsdir
	global cuda_inc

	cuda_rpm = ""
	libpath = ""
	binpath = ""
	os.system("clear")
	printstdout(chheader())
	if len(mods) > 1 and "all" in mods :
		sys.exit(-1)
	#uninstall_targets(["tools", "nvidia"],1)
	uninstall_targets(["tools"],1)
	os.system("clear")
	printstdout(chheader())
	print "\nPlease check %s/gdr_install.log file for install logs"%(pwd)
	#printstdout("\nInstalling :\n\n")
	printstdout("\n\n")
	os.chdir(pwd)
	getNVIDIApath()
	#copynvsymvers()
	copyPeerdirectconf()
	#print "mod=%s ::Inside install_targets::"%mods
	if "nvidia" in mods :
		uninstall_targets(["nvidia"],1)
		printstdout("Installing NVIDIA peer memory:\t")
		os.chdir(srcdir + os.sep + "nvidia_peer_memory" )
		#cmd = "make && make install"
		commands.getstatusoutput("sh build_module.sh")
		commands.getstatusoutput("rpmbuild --rebuild /tmp/nvidia_peer_memory-1.0-7.src.rpm")
		os.chdir("/root/rpmbuild/RPMS/x86_64/")
		cmd = "rpm -ivh nvidia_peer_memory-1.0-7.x86_64.rpm"
		installprocess("NVIDIA peer memory",cmd)
		os.chdir(pwd)
		
	if "chiwarp" in mods:
		printstdout("Installing Chelsio iwarp driver:")
		#restoreautoconf()
		os.chdir(pwd)
		cmd = "make iwarp_install"
		installprocess("Chelsio iwarp driver",cmd)

	if "tools" in mods :
		# Install openmpi-3.1.2
		print "\nStarting Tools installation: \nInstalling: \n"
		printstdout("openmpi-%s:"%(OMPI_VERSION))
		os.chdir(toolsdir + os.sep + "openmpi-%s"%(OMPI_VERSION) )
		commands.getstatusoutput("make distclean")
		cmd = "./configure --prefix=/usr/mpi/gcc/ompi-"+ OMPI_VERSION +"-gdr --with-wrapper-ldflags=-Wl,-rpath,/lib " + \
			"--disable-vt --enable-orterun-prefix-by-default  --disable-io-romio --enable-picky --with-cuda="+ cuda_inc + \
			" && make && make install"
		installprocess("openmpi-%s"%(OMPI_VERSION),cmd)
		
		# Install osu-micro-benchmarks
		printstdout("osu-micro-benchmarks-%s with openmpi:"%(OSU_MB_VERSION))
		os.chdir(toolsdir + os.sep + "osu-micro-benchmarks-" + OSU_MB_VERSION )
		commands.getstatusoutput("make distclean")
		cmd = "./configure CC=/usr/mpi/gcc/ompi-"+ OMPI_VERSION +"-gdr/bin/mpicc --enable-cuda \
			--with-cuda="+ cuda_inc + " && make"
		installprocess("osu-micro-benchmarks-"+OSU_MB_VERSION,cmd)
		#From  mpi/pt2pt  Copy osu_bw  and osu_latency  binaries generated  to /usr/mpi/gcc/ompi-1.8.4-gdr/tests/osu_bench
		osu_path = "/usr/mpi/gcc/ompi-"+OMPI_VERSION+"-gdr/tests"
		osu_bench_path = osu_path +"/osu_bench"
		if not os.path.isdir(osu_bench_path) :
			os.makedirs(osu_bench_path)
		for copy in ['osu_bibw','osu_bw','osu_latency','osu_latency_mt','osu_mbw_mr','osu_multi_lat'] :
			if os.path.isfile("mpi/pt2pt/"+copy):
				shutil.copy("mpi/pt2pt/"+copy, osu_bench_path+"/")
		for copy in ['osu_allgather', 'osu_allgatherv', 'osu_allreduce', 'osu_alltoall',  'osu_alltoallv', 'osu_barrier', 'osu_bcast', 'osu_gather', 'osu_gatherv', \
				'osu_reduce', 'osu_reduce_scatter', 'osu_scatter', 'osu_scatterv' ] :
			if os.path.isfile("mpi/collective/"+copy):
				shutil.copy("mpi/collective/"+copy, osu_bench_path+"/")
		for copy in ['osu_acc_latency','osu_get_bw','osu_get_latency','osu_passive_acc_latency','osu_passive_get_bw','osu_passive_get_latency','osu_passive_put_bw', \
				'osu_passive_put_latency','osu_put_bibw','osu_put_bw','osu_put_latency' ] :
			if os.path.isfile("mpi/one-sided/"+copy):
				shutil.copy("mpi/one-sided/"+copy, osu_bench_path+"/")
				
		# Install perftest
		printstdout("perftest:")
		os.chdir(toolsdir + os.sep + "perftest" )
		commands.getstatusoutput("make distclean")
		cmd = "./autogen.sh ; CUDA_H_PATH=" + cuda_inc + "/include/cuda.h ./configure && make && make install"
		installprocess("perftest",cmd)
		
		#restoreautoconf()
		
	cmd = "ldconfig"
	sts, out = commands.getstatusoutput(cmd)

def getCUDApath():
	global cuda_inc
	global pwd
	global cuda_libpkg
	cudalibpath = ""
	cmd = "rpm -qa | grep -c cuda-cudart"
	sts, out = commands.getstatusoutput(cmd)
	cudartlibs = int(out)
	if cudartlibs < 1 :
		print "CUDA is not present in the machine... Please install CUDA packages and restart the installation"
		sys.exit(1)
		
	else :
		cmd = "for i in $(rpm -qa | grep cuda-cudart| sort -fr) ; do if [[ $(echo $i | grep -c \"dev\" ) -eq 0 ]] ;then echo $i ; break ; fi ; done "
		sts, out = commands.getstatusoutput(cmd)
		cuda_libpkg = out
		cmd = "rpm -ql %s | grep libcudart.so | head -n 1 | awk -F \"targets\" '{print $1}'"%cuda_libpkg
		sts, out = commands.getstatusoutput(cmd)
		cudalibpath = out
	cuda_inc = cudalibpath

def getNVIDIApath():
	global nvidiasrc
	
	if nvidiasrc == None :
		cmd = "modinfo -F version nvidia"
		sts, out = commands.getstatusoutput(cmd)
		if sts != 0 :
			print "Unable to find nvidia driver."
			print "Please install NVIDIA driver and restart the installation."
			sys.exit(1)
		NVIDIA_VERSION = out
		nvidiasrc = "/usr/src/nvidia-" + out
		for nsrc in ["/usr/src/nvidia-"+out, "/var/lib/dkms/nvidia/"+out+"/source/"]:
			if os.path.isdir(nsrc) :
				nvidiasrc = nsrc
				break
		else :
			print "Unable to find NVIDIA source path."
			print "Please provide the NVIDIA source path using -n <nvidia_src_path>."
			sys.exit(1)

def copynvsymvers():
	global nvidiasrc
	getNVIDIApath()
	curpwd = os.getcwd()
	os.chdir(nvidiasrc)
	printstdout("Creating NVIDIA symvers file")
	print "\n"
	cmd = "make"
	sts, out = commands.getstatusoutput(cmd)
	cmd = "grep nvidia_p2p Module.symvers > nv.symvers"
	sts, out = commands.getstatusoutput(cmd)
	shutil.copyfile(nvidiasrc + os.sep + "nv.symvers", \
			srcdir + os.sep + "nvidia_peer_memory" + os.sep + "nv.symvers")

def restoreautoconf():
	toolsdir = pwd + os.sep + "tools"
	os.chdir(toolsdir + os.sep + "autoconf-"+AUTOCONF_VERSION) 
	commands.getstatusoutput("./configure --bindir=/usr/bin ; make uninstall")
	os.chdir(toolsdir + os.sep + "automake-"+AUTOMAKE_VERSION) 
	commands.getstatusoutput("./configure --bindir=/usr/bin ; make uninstall")
	commands.getstatusoutput("rpm -e autoconf automake --nodeps --allmatches")
	os.chdir(toolsdir)
	commands.getstatusoutput("rpm -ivh autoconf-2.63-5.1.el6.noarch.rpm automake-1.11.1-1.2.el6.noarch.rpm ")

def installprocess(module,cmd):
	global fail_ban
	def runCmd(Cmd):
		k = subprocess.Popen(
			Cmd,
			stdout=handler,
			stderr=handler,
			shell=True,
			executable="/bin/bash",
			stdin=None)
		k.wait()
		ret = k.poll()
		k.poll()
		return cmd,k.returncode,k.pid
        c,ret,pid = runCmd(cmd)
	if ret != 0 :
		printstdout(FAIL+"\tFailed"+RESET+"\n")
		fail_ban += FAIL + "%s installation failed"%(module) + RESET + "\n"
		#print FAIL + "%s installation failed"%(module) + RESET
	else:
		printstdout(GREEN+"\tDone"+RESET+"\n")
	

def copyPeerdirectconf():
	# Create peer-direct.conf file.
	global pwd
	peer_paths = ""
	confFile = os.path.join(pwd,"tools","peer-direct.conf")
	peerHandler = open(confFile,"w")
	toolsdir = pwd + os.sep + "tools"
	peer_paths+="/usr/local/lib\n/usr/local/lib64\n"
	cmd = "rpm -ql %s | grep libcudart.so | head -n 1"%cuda_libpkg
	sts, str = commands.getstatusoutput(cmd)
	k=str.split("/")
	del k[-1]
	peer_paths+=os.sep.join(k) + "\n"
	peerHandler.write(peer_paths)
	peerHandler.close()
	if os.path.isfile(confFile) :
		if os.path.isfile("/etc/ld.so.conf.d/peer-direct.conf"):
			os.remove("/etc/ld.so.conf.d/peer-direct.conf")
		shutil.copyfile(confFile, "/etc/ld.so.conf.d/peer-direct.conf")
	cmd = "ldconfig"
	sts, out = commands.getstatusoutput(cmd)	

def chheader():
	ret  = "##############################################\n"
	ret += "       Chelsio GPUDirect RDMA Installer\n"
	ret += "##############################################\n"
	return ret

def printstdout(text):
	sys.stdout.write(text)
	sys.stdout.flush()

def shell(cmd):
        sts, out = commands.getstatusoutput(cmd)
        return (sts,out.strip())
	
def uninstall_targets(target,op=0):
	global pwd
	srcdir = pwd + os.sep + "src"
	toolsdir = pwd + os.sep + "tools" + os.sep + "gdr_tools"
	if op != 2 :
		os.system("clear")
		printstdout(chheader())
		if op == 1 :
			print "\nCleaning up the system before installation.\nUninstalling previously installed drivers and tools."
		print "\nPlease check %s/gdr_uninstall.log file for uninstall logs\n"%(pwd)
	if "nvidia" in target :
		print "Uninstalling NVIDIA peer memory \n"
		os.chdir(srcdir + os.sep + "nvidia_peer_memory" )
		#cmd = "make uninstall"
		cmd = "rpm -e nvidia_peer_memory-1.0-7.x86_64"
		subprocess.call(cmd,stdout=unhandler,stderr=unhandler,shell=True)
		os.chdir(pwd)
		
	if 'tools' in target :
		print "Uninstalling Tools\n"
		ompi_test = "/usr/mpi/gcc/ompi-"+ OMPI_VERSION +"-gdr/tests"
		if os.path.isdir(ompi_test):
			shutil.rmtree(ompi_test)
		os.chdir(toolsdir + os.sep + "openmpi-"+OMPI_VERSION )
		cmd = "./configure --prefix=/usr/mpi/gcc/ompi-"+ OMPI_VERSION +"-gdr --with-wrapper-ldflags=-Wl,-rpath,/lib \
			--disable-vt --enable-orterun-prefix-by-default  --disable-io-romio --enable-picky \
			&& make uninstall"
		subprocess.call(cmd,stdout=unhandler,stderr=unhandler,shell=True)
		os.chdir(toolsdir + os.sep + "perftest" )
		cmd = "./configure && make uninstall"
		subprocess.call(cmd,stdout=unhandler,stderr=unhandler,shell=True)
			
	
	if 'chiwarp' in target :
		print "Uninstalling Chelsio iWARP Driver\n"
		os.chdir(pwd)
		cmd = "make iwarp_uninstall toe_uninstall nic_offload_uninstall"
		subprocess.call(cmd,stdout=unhandler,stderr=unhandler,shell=True)
		os.chdir(pwd)
		
		print "Uninstallation Completed.\n"

def kernel_check():
	global supported_kver
	kernel_ver =  shell('uname -r')[1]
	arch = shell('uname -m')[1]
	if re.search(('|').join(supported_kver),kernel_ver) == None:
		print FAIL + 'The %s kernel version is not supported.'%(kernel_ver)+ RESET +'\nThe package is supported only with below kernels,\n' \
			+ ('\n').join(supported_kver)
		sys.exit(1)
	if (arch != "x86_64") :
		print BLUE + 'The %s architecture is not supported.\n'%(arch) + RESET
		print BLUE + 'The package supports only x86_64 architecture.' + RESET
		sys.exit(1)

def dist_check():
	global dist
	global DISTRO
	global repomgr
	global NVIDIA_VERSION

	if os.path.isfile('/etc/issue'):
		dist_rpm = shell('rpm -qf /etc/issue | head -1')[1]
		dist_rpm = shell('rpm -q --queryformat "[%{NAME}]-[%{VERSION}]-[%{RELEASE}]" ' + dist_rpm)[1]
	else:
		dist_rpm = "unsupported"

	if re.search('redhat-release-.*-7.5|centos-release-7-5',dist_rpm) != None:
		dist = 'rhel7u5'
		DISTRO = 'RHEL7.5'
		repomgr = 'yum -y'
		NVIDIA_VERSION = "410.72" 
	else :
		print BLUE + 'The Operating System is not supported.\n' + RESET
		print BLUE + 'For the list of Supported Platforms and Operating Systems see' + RESET
		print BLUE + '%s/docs/README.txt'%(pwd) + RESET
		
def peer_mem_check():
	
	kernel_ver = os.uname()[2]
	peer_mem_path = "/lib/modules/"+kernel_ver+"/build/include/rdma/peer_mem.h"
	if not os.path.isfile(peer_mem_path):
		print FAIL + 'nvidia peer mem is not supported with %s kernel version .'%(kernel_ver)+ RESET
                sys.exit(1)

	
if __name__ == "__main__":
	handler = open("gdr_install.log","w")
	unhandler = open("gdr_uninstall.log","w")
	fail_ban = ""
	parser = OptionParser(
	usage = "usage: %prog [options] arg\n\nPlease use %prog -h to print help",
	description='Chelsio GPUdirect installer')
	
	inGroup = OptionGroup(parser, "Install Options")
	inGroup.add_option("-i", dest="target", help="Targets to be installed: \
								all - Install nvidia driver, Tools")
	inGroup.add_option("-n", "--nvidiasrc", dest="path", help="Provide NVIDIA source path" )
	
	unGroup = OptionGroup(parser, "Uninstall Options")
	unGroup.add_option("-u", dest="target", help="Targets to be uninstalled: \
								all - uninstall nvidia driver, Tools")
	
	parser.add_option_group(inGroup)
	parser.add_option_group(unGroup)
	
	a = sys.argv[1:]
	(options, args) = parser.parse_args(sys.argv[1:])
	
	kernel_check()
	dist_check()
	peer_mem_check()
	getCUDApath()
	handler.write(chheader())
	handler.write("CUDA_PATH : "+cuda_inc )
	handler.flush()
	
	try:
		if "-i" in a and "-u" in a :
			print "Please provide install or uninstall option."
			parser.print_help()
			sys.exit(1)
		if "-i" in a:
			install = True
			target = options.target
			if options.path :
				nvidiasrc = options.path
			if "all" in target or target == "all" :
				targs = ["nvidia", "chiwarp", "tools" ]
			else :
				targs = target
			install_targets(targs)
			if fail_ban != "" :
				print "\n" + fail_ban
		elif "-u" in a :
			uninstall = True
			target = options.target
			if "all" in target or target == "all" :
				targs = ["nvidia", "chiwarp", "tools" ]
			else :
				targs = target
			uninstall_targets(targs)
	except IndexError:
		print "\nChelsio GPUDirect installer\n"
		print "Please execute \"gdr_setup.py -h\" to print help\n"
	handler.close()
	unhandler.close()


