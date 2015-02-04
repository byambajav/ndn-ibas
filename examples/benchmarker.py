from subprocess import Popen, PIPE

def simpleBenchmark():
    print "sigType,success,n,loadSize,publishSec,aggregationSec,verificationSec"
    for load in range(0, 151):
        args = ("../build/examples/ibas-benchmark", "4", "100", "%s"%str(load * 10), "0")
        popen = Popen(args, stdout=PIPE)
        popen.wait()
        output = popen.stdout.read()
        output = output.replace('\n', '')
        print output

def restartNfdDaemon():
    nfdStopProcess = Popen("nfd-stop")
    nfdStopProcess.wait()
    nfdStartProcess = Popen("nfd-start")
    nfdStartProcess.wait()

# Not working
def communicationBenchmark():
    # restartNfdDaemon() # Just to make sure

    print "n,fail,success,totalTime"
    for load in range(0, 10, 10):
        # Run Alice, GovernmentOffice, and Bob in parallel
        commands = [
            ('../build/examples/alice', '4', '%s'%load),
            ('../build/examples/government-office'),
            ('../build/examples/bob', '10')
        ]
        processes = [Popen(cmd) for cmd in commands]

        # Wait for Bob's completion
        processes[2].wait()
        # print "Bob finished"

        # Kill Alice and GovernmentOffice's processes
        processes[0].terminate()
        processes[0].wait()
        processes[1].terminate()
        processes[1].wait()
        # print "Kill finished"

communicationBenchmark()
