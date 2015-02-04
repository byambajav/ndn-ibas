import subprocess

def simpleBenchmark():
    print "sigType,success,n,loadSize,publishSec,aggregationSec,verificationSec"
    for load in range(0, 150):
        args = ("../build/examples/ibas-benchmark", "4", "100", "%s"%str(load * 10), "0")
        popen = subprocess.Popen(args, stdout=subprocess.PIPE)
        popen.wait()
        output = popen.stdout.read()
        output = output.replace('\n', '')
        print output

def communicationBenchmark():
    # TODO
