# Author: Hubert Kario, (c) 2018
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys
import getopt
from itertools import chain
from random import sample

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        ResetHandshakeHashes
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType
from tlslite.extensions import ALPNExtension, TLSExtension


from tlsfuzzer.utils.lists import natural_sort_keys


version = 1


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname    name of the host to run the test against")
    print("                localhost by default")
    print(" -p port        port number to use for connection, 4433 by default")
    print(" probe-name     if present, will run only the probes with given")
    print("                names and not all of them, e.g \"sanity\"")
    print(" -e probe-name  exclude the probe from the list of the ones run")
    print("                may be specified multiple times")
    print(" -n num         only run `num` random tests instead of a full set")
    print("                (excluding \"sanity\" tests)")
    print(" --no-renego-close expect a connection close, after no_renego alert")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    no_renego_close = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:n:", ["help", "no-renego-close"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '-n':
            num_limit = int(arg)
        elif opt == '--no-renego-close':
            no_renego_close = True
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    conversations = {}

    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET /?Renegotiation_Test=tlsfuzzer HTTP/1.0\r\n\r\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity"] = conversation

    # renegotiation
    conversation = Connect(host, port)
    node = conversation

    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    ext = {ExtensionType.renegotiation_info:None}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    ext = {ExtensionType.renegotiation_info: None}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    # 2nd handshake
    node = node.add_child(ResetHandshakeHashes())
    ext = {ExtensionType.renegotiation_info:None}
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               session_id=bytearray(0),
                                               extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.no_renegotiation))
    if no_renego_close:
        node = node.add_child(ExpectAlert(AlertLevel.warning,
                                          AlertDescription.close_notify))
        node = node.add_child(ExpectClose())
    else:
        # send GET request
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET /?Renegotiation_Test=tlsfuzzer HTTP/1.0\r\n")))
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b'\r\n')))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
    conversations["try secure renegotiation with GET after 2nd CH"] = conversation

    # renegotiation
    conversation = Connect(host, port)
    node = conversation

    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    ext = {ExtensionType.renegotiation_info:None}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    ext = {ExtensionType.renegotiation_info: None}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    # send incomplete GET request
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET /?Renegotiation_Test=tlsfuzzer HTTP/1.0\r\n")))
    # 2nd handshake
    node = node.add_child(ResetHandshakeHashes())
    ext = {ExtensionType.renegotiation_info:None}
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               session_id=bytearray(0),
                                               extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.no_renegotiation))
    if no_renego_close:
        node = node.add_child(ExpectAlert(AlertLevel.warning,
                                          AlertDescription.close_notify))
        node = node.add_child(ExpectClose())
    else:
        # finish the GET request
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b'\r\n')))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
    conversations["try secure renegotiation with incomplete GET"] = conversation

    # insecure renegotiation
    conversation = Connect(host, port)
    node = conversation

    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    # 2nd handshake
    node = node.add_child(ResetHandshakeHashes())
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               session_id=bytearray(0)))
    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.no_renegotiation))
    if no_renego_close:
        node = node.add_child(ExpectAlert(AlertLevel.warning,
                                          AlertDescription.close_notify))
        node = node.add_child(ExpectClose())
    else:
        # send GET request
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET /?Renegotiation_Test=tlsfuzzer HTTP/1.0\r\n")))
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b'\r\n')))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
    conversations["try insecure (legacy) renegotiation with GET after 2nd CH"] = conversation

    # insecure renegotiation
    conversation = Connect(host, port)
    node = conversation

    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    # send incomplete GET request
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET /?Renegotiation_Test=tlsfuzzer HTTP/1.0\r\n")))
    # 2nd handshake
    node = node.add_child(ResetHandshakeHashes())
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               session_id=bytearray(0)))
    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.no_renegotiation))
    if no_renego_close:
        node = node.add_child(ExpectAlert(AlertLevel.warning,
                                          AlertDescription.close_notify))
        node = node.add_child(ExpectClose())
    else:
        # finish the GET request
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b'\r\n')))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
    conversations["try insecure (legacy) renegotiation with incomplete GET"] = conversation


    # run the conversation
    good = 0
    bad = 0
    failed = []
    if not num_limit:
        num_limit = len(conversations)

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throughout
    sanity_tests = [('sanity', conversations['sanity'])]
    regular_tests = [(k, v) for k, v in conversations.items() if k != 'sanity']
    sampled_tests = sample(regular_tests, min(num_limit, len(regular_tests)))
    ordered_tests = chain(sanity_tests, sampled_tests, sanity_tests)

    for c_name, c_test in ordered_tests:
        if run_only and c_name not in run_only or c_name in run_exclude:
            continue
        print("{0} ...".format(c_name))

        runner = Runner(c_test)

        res = True
        try:
            runner.run()
        except Exception:
            print("Error while processing")
            print(traceback.format_exc())
            res = False

        if res:
            good += 1
            print("OK\n")
        else:
            bad += 1
            failed.append(c_name)

    print("Verify that the server disabled renegotiation (both legacy and secure)")
    print("version: {0}\n".format(version))

    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))
    failed_sorted = sorted(failed, key=natural_sort_keys)
    print("  {0}".format('\n  '.join(repr(i) for i in failed_sorted)))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
