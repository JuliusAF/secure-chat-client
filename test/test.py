#!/usr/bin/env python3 

import locale
import os
import random
import shutil
import subprocess
import sys
import time

import procman

# exit code:
# - 0: no errors or warnings
# - 1: warning(s) that should be fixed
# - 2: error that should be fixed and caused tests to be aborted

warnings=False
tcpport_last=0
testindex=0
TCP_PORT_MIN=5000
TCP_PORT_MAX=32767

class CommandResult:
  def __init__(self):
    self.is_done = False

  def report(self, success):
    if self.is_done: return
    sys.stdout.write(" %s\n" % ("success" if success else "failed"))
    self.is_done = True

def die(msg):
  sys.stderr.write("%s\n" % msg)
  sys.exit(2)

def get_tcpport():
  global tcpport_last
  # avoid reusing ports in case an earlier server has not released the port yet
  if tcpport_last:
    tcpport_last += 1
    if tcpport_last > TCP_PORT_MAX:
      tcpport_last = tcpport_last - TCP_PORT_MAX + TCP_PORT_MIN
  else:
    tcpport_last = random.randint(TCP_PORT_MIN, TCP_PORT_MAX)
  return tcpport_last

def list_files_mtimes(dir):
  fileset = set()
  for root, dirs, files in os.walk(dir):
    for file in files:
      path = os.path.join(root, file)
      fileset.add((path, os.path.getmtime(path)))
  return fileset

def run_make(dir, target):
  global warnings

  sys.stdout.write("running make %s..." % (target))
  cmdresult = CommandResult()
  try:
    result = subprocess.run(["make", target], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=dir)
  except OSError as e:
    cmdresult.report(False)
    sys.stderr.write("error: failed to start make: %s\n" % (e.strerror))
    sys.exit(2)

  if result.returncode != 0:
    cmdresult.report(False)
    if result.returncode < 0:
      sys.stderr.write("error: make failed with signal %d\n" % (-result.returncode))
    else:
      sys.stderr.write("error: make failed with exit code %d\n" % (result.returncode))

    stderrtext = result.stderr.decode(locale.getpreferredencoding())
    procman.print_std("make", "stderr", stderrtext)
    sys.exit(2)

  if result.stderr:
    cmdresult.report(False)
    sys.stderr.write("warning: make gave warning(s)\n")
    stderrtext = result.stderr.decode(locale.getpreferredencoding())
    procman.print_std("make", "stderr", stderrtext)
    warnings = True
    return

  cmdresult.report(True)

def callback_check_start_one(pm):
  # executed with one client
  pass

def callback_check_start_two(pm):
  # executed with two clients
  pass

def callback_check_register(pm):
  # executed with one client
  pm.sendinput(1, "/register erik hunter2\n")

def callback_check_login(pm):
  # executed with one client
  pm.sendinput(1, "/login erik hunter2\n")

REGEXP_TIMESTAMP = "20[0-9][0-9]-[01][0-9]-[0-3][0-9] [0-2][0-9]:[0-5][0-9]:[0-6][0-9]"
REGEXP_PUBMSG1 = REGEXP_TIMESTAMP + " erik: pubmsg1"
REGEXP_PUBMSG2 = REGEXP_TIMESTAMP + " erik: pubmsg2"

def callback_check_pubmsg_send(pm):
  # executed with one client
  pm.sendinput(1, "/login erik hunter2\n")
  pm.sendinput(1, "pubmsg1\n")
  pm.waitall()
  pm.matchoutput(1, [REGEXP_PUBMSG1])

def callback_check_pubmsg_retr(pm):
  # executed with one client
  pm.sendinput(1, "/login erik hunter2\n")
  pm.waitall()
  pm.matchoutput(1, [REGEXP_PUBMSG1])

def callback_check_pubmsg_recv(pm):
  # executed with one client
  pm.sendinput(1, "/login erik hunter2\n")
  pm.sendinput(2, "/register user2 iloveyou\n")
  pm.sendinput(1, "pubmsg2\n")
  pm.waitall()
  pm.matchoutput(1, [REGEXP_PUBMSG1, REGEXP_PUBMSG2])
  pm.matchoutput(2, [REGEXP_PUBMSG1, REGEXP_PUBMSG2])

def interact(sourcedir, tmpdir, clientcount, callback, msg):
  global testindex, warnings

  # show progress
  sys.stdout.write(msg)
  cmdresult = CommandResult()

  # each test gets their own tempdir for output
  testindex += 1
  tmpdirtest = os.path.join(tmpdir, "test%d" % (testindex))

  # create all processes
  pm = procman.ProcessManager(sourcedir, tmpdirtest, get_tcpport(), clientcount, cmdresult)
  try:
    # interact with processes to perform test
    callback(pm)
  finally:
    # clean up and return status
    pm.waitall()
    warnings = warnings or pm.error
    cmdresult.report(True)

def check_build(dir):
  sys.stdout.write("executables built? ...")
  cmdresult = CommandResult()

  serverpath = os.path.join(dir, "server")
  if not os.path.isfile(serverpath):
    cmdresult.report(False)
    die("file %s does not exist" % (serverpath))

  clientpath = os.path.join(dir, "client")
  if not os.path.isfile(clientpath):
    cmdresult.report(False)
    die("file %s does not exist" % (clientpath))

  cmdresult.report(True)

def check_clean(dir):
  global warnings

  sys.stdout.write("source directory clean? ...")
  cmdresult = CommandResult()

  # verify that the directory contains no files that must be deleted by make clean
  for name in os.listdir(dir):
    if name in ["server", "client", "chat.db"] or name.endswith(".o"):
      cmdresult.report(False)
      sys.stderr.write("warning: file %s remains after clean\n" % (os.path.join(dir, name)))
      warnings = True

  cmdresult.report(True)

def check_filediff(dir, filesdiff, isnew):
  global warnings
  # verify that only files have been modified that the assignment allows
  pathchatdb = os.path.join(dir, "chat.db")
  pathclientkeys = os.path.join(dir, "clientkeys")
  pathserverkeys = os.path.join(dir, "serverkeys")
  pathttpkeys = os.path.join(dir, "ttpkeys")
  pathtesttmp = os.path.join(dir, "test-tmp")
  for path, mtime in sorted(filesdiff):
    if path == pathchatdb: continue
    if path.startswith(pathchatdb + "-"): continue
    if path.startswith(pathclientkeys): continue
    if path.startswith(pathserverkeys): continue
    if path.startswith(pathttpkeys): continue
    if path.startswith(pathtesttmp): continue
    
    sys.stderr.write("warning: file %s has been %s or modified by the program\n" % (path, "created" if isnew else "deleted"))
    warnings = True

def check_files(dir, filesbefore, filesafter):
  check_filediff(dir, filesbefore - filesafter, False)
  check_filediff(dir, filesafter - filesbefore, True)

print("""secchat test framework
----------------------

This program tests some of the basic functionality required in the SecChat
assignment for the Secure Programming course. If any of the tests fail,
you have not correctly implemented these requirements, and the chance of getting
a sufficient grade is rather low. If you DO pass the test, it is no guarantee
that you will also pass the assignment because many requirements cannot be
tested automatically.

usage:
  test.py path-to-source

The path-to-source parameter specifies the directory where your Makefile is
stored, and where your programs client and server are created after compilation.
Other files may be stored in subdirectories of this directory. Make sure your
programs work no matter where path-to-source is located, so avoid absolute paths
in your code or Makefile.


test progress
-------------
""")

# parameter sanity test
if len(sys.argv) < 2: die("path-to-source not specified")
if len(sys.argv) > 2: die("unexpected parameter(s)")

sourcedir = sys.argv[1]
if not os.path.isdir(sourcedir): die("directory %s does not exist" % (sourcedir))

makefile = os.path.join(sourcedir, "Makefile")
if not os.path.isfile(makefile): die("file %s does not exist" % (makefile))

# make clean, and verify cleanness (avoids stale files)
run_make(sourcedir, "clean")
check_clean(sourcedir)

# build the code
run_make(sourcedir, "all")
check_build(sourcedir)

# clear temp dir
tmpdir = os.path.join(sourcedir, "test-tmp")
if os.path.isdir(tmpdir): shutil.rmtree(tmpdir)

# remember which files exist
filesbefore = list_files_mtimes(sourcedir)

# run the actual experiments
interact(sourcedir, tmpdir, 1, callback_check_start_one,   "running with single client...")
interact(sourcedir, tmpdir, 2, callback_check_start_two,   "running with two clients...")
interact(sourcedir, tmpdir, 1, callback_check_register,    "testing /register...")
interact(sourcedir, tmpdir, 1, callback_check_login,       "testing /login...")
interact(sourcedir, tmpdir, 1, callback_check_pubmsg_send, "testing public message send...")
interact(sourcedir, tmpdir, 1, callback_check_pubmsg_retr, "testing public message retrieve...")
interact(sourcedir, tmpdir, 2, callback_check_pubmsg_recv, "testing public message receive...")

# check whether any files were modified that should not have been
filesafter = list_files_mtimes(sourcedir)
check_files(sourcedir, filesbefore, filesafter)

# done!
if warnings: sys.exit(1)
