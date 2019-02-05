#!/usr/bin/env python3
# -*- mode: python; coding: utf-8; -*-

"""Amend flow records with resolved fields.

Available resolutions are: dns_ptr, dns_a, dns_aaaa, ent_services."""


import sys
import socket

import pytrap


__author__ = "Ulrik Haugen <ulrik.haugen@liu.se>"
__copyright__ = "Copyright 2018 Linköping university"
__license__ = """LICENSE TERMS

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in
   the documentation and/or other materials provided with the
   distribution.
3. Neither the name of the Company nor the names of its contributors
   may be used to endorse or promote products derived from this
   software without specific prior written permission.

ALTERNATIVELY, provided that this notice is retained in full, this
product may be distributed under the terms of the GNU General Public
License (GPL) version 2 or later, in which case the provisions
of the GPL apply INSTEAD OF those given above.

This software is provided ``as is'', and any express or implied
warranties, including, but not limited to, the implied warranties of
merchantability and fitness for a particular purpose are disclaimed.
In no event shall the company or contributors be liable for any
direct, indirect, incidental, special, exemplary, or consequential
damages (including, but not limited to, procurement of substitute
goods or services; loss of use, data, or profits; or business
interruption) however caused and on any theory of liability, whether
in contract, strict liability, or tort (including negligence or
otherwise) arising in any way out of the use of this software, even
if advised of the possibility of such damage."""


class Resolver:
    """Resolver methods and types/length promises."""

    # Maxumum length of domain names returned (see rfc 1035 section
    # 2.3.4)
    maximumnamelength = 253
    # Maximum length of service named returned
    maximumservicelength = 255

    # Lower case protocol name by protocol number
    protobynum = {proto: name[len("IPPROTO_"):].lower()
                  for name, proto
                  in vars(socket).items()
                  if name.startswith("IPPROTO_")}

    def typesbyresolution(self):
        """Return type requirements and promises by resolution method name.

        Requirements and promises are expressed as Unirec types."""
        return {'dns_ptr': (('ipaddr',),
                            ('string', self.maximumnamelength)),
                'dns_a': (('string',),
                          ('ipaddr', )),
                'dns_aaaa': (('string',),
                             ('ipaddr', )),
                'ent_services': (('uint16', 'uint8'),
                                 ('string', self.maximumservicelength))}

    def dns_ptr(self, urinput, addrfield):
        """Return the first resolved domain name for the address.

        The address is specified in _addrfield_ of _urinput_. The
        domain name is returned as a string. If no domain name can be
        resolved n/a is returned."""
        try:
            addr = getattr(urinput, addrfield)
            family = {True: socket.AF_INET,
                      False: socket.AF_INET6}[addr.isIPv4()]
            return socket.getnameinfo((str(addr),
                                       # fudge port
                                       0),
                                      socket.NI_NAMEREQD
                                      # select the domain name and
                                      # ensure we don't return a
                                      # longer string than promised
                                      | family)[0][:self.maximumnamelength]
        except Exception as err:  # pylint:disable=broad-except
            print("Error: Received exception {}"
                  " doing ptr lookup for {}".format(
                      err, getattr(urinput, addrfield, "unavailable address")))
            return "n/a"

    def dns_a(self, urinput, namefield):
        """Return the first resolved ip4 address for the domain name.

        The domain name is specified in _addrfield_ of _urinput_. The
        ip4 address is returned as an ipaddr. If no address can be
        resolved 0.0.0.0 is returned."""
        try:
            return pytrap.UnirecIPAddr(
                socket.getaddrinfo(getattr(urinput, namefield),
                                   # fudge port
                                   0,
                                   # truncate list of answers to first
                                   # and select the address
                                   socket.AF_INET)[0][4][0])
        except Exception as err:  # pylint:disable=broad-except
            print("Error: Received exception {}"
                  " doing a lookup for {}".format(
                      err, getattr(urinput, namefield, "unavailable name")))
            return pytrap.UnirecIPAddr("0.0.0.0")

    def dns_aaaa(self, urinput, namefield):
        """Return the first resolved ip6 address for the domain name.

        The domain name is specified in _addrfield_ of _urinput_. The
        ip6 address is returned as an ipaddr. If no address can be
        resolved :: is returned."""
        try:
            return pytrap.UnirecIPAddr(
                socket.getaddrinfo(getattr(urinput, namefield),
                                   # fudge port
                                   0,
                                   # truncate list of answers to first
                                   # and select the address
                                   socket.AF_INET6)[0][4][0])
        except Exception as err:  # pylint:disable=broad-except
            print("Error: Received exception {}"
                  " doing aaaa lookup for {}".format(
                      err, getattr(urinput, namefield, "unavailable name")))
            return pytrap.UnirecIPAddr("::")

    def ent_services(self, urinput, portfield, protofield):
        """Return the service name for the service.

        The service is specified by _portfield_ and _protofield_ of
        _urinput_. The service name is returned as a string truncated
        to maximumservicelength characters. if no service name can be
        resolved n/a is returned."""
        try:
            return socket.getservbyport(
                getattr(urinput, portfield),
                self.protobynum[getattr(
                    # ensure we don't return a longer string than
                    # promised
                    urinput, protofield)])[:self.maximumservicelength]
        except Exception as err:  # pylint:disable=broad-except
            print("Error: Received exception {}"
                  " doing services lookup for {}/{}".format(
                      err,
                      getattr(urinput, portfield, "unavailable port"),
                      getattr(urinput, protofield, "unavailable protocol")))
            return "n/a"


def parseargs(programargs, resolver):
    """Parse program args to determine run time configuration."""
    from argparse import ArgumentParser
    parser = ArgumentParser(description=__doc__,
                            epilog="""All fields specified as infields
                            in resolvspec parameters must be supplied
                            in the urformat parameter for this module
                            to start. Note though that the downstream
                            module will fail if it requires non
                            resolved fields you do not specify in the
                            uformat parameter.""")
    reqgroup = parser.add_argument_group('required arguments')
    reqgroup.add_argument("-i", "--ifcspec",
                          required=True,
                          help="See"
                          " https://nemea.liberouter.org/trap-ifcspec/",
                          metavar="ifcspec")
    reqgroup.add_argument('-u', '--urformat',
                          required=True,
                          help="Specify required unirec input format",
                          metavar="urformat")
    reqgroup.add_argument('-r', '--resolvspec',
                          required=True,
                          nargs=3, dest='resolvspecs', action='append',
                          help="Specify field(s), what lookup to do of"
                          " it/them and where to put the result",
                          metavar=("infield[/infield]",
                                   "resolution",
                                   "outfield"))
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="Enable verbose output")

    args = parser.parse_args(list(programargs))

    infields = [type_name.split(' ')
                for type_name
                in args.urformat.split(',')]
    infieldtypebyname = {name: ftype
                         for ftype, name
                         in infields}
    typesbyresolution = resolver.typesbyresolution()

    validatedresolvspecs = []
    outfields = []
    for resolvspec in args.resolvspecs:
        fieldstoresolvestring, resolution, outfield = resolvspec
        fieldstoresolve = fieldstoresolvestring.split('/')

        if len(fieldstoresolve) > 2:
            parser.error("Too many infields in: {}".format(
                ' '.join(resolvspec)))

        if resolution not in typesbyresolution:
            parser.error("Unrecognised resolution: {},"
                         " choose from: {}.".format(
                             resolution,
                             ', '.join(sorted(typesbyresolution.keys()))))

        resolutionintypes = typesbyresolution[resolution][0]

        if len(fieldstoresolve) != len(resolutionintypes):
            parser.error("Too many/not enough infields ({}) for"
                         " selected resolution ({}), needed"
                         " {}".format(fieldstoresolvestring,
                                      resolution,
                                      len(resolutionintypes)))

        for fieldnum, fieldtoresolve in enumerate(fieldstoresolve):
            if fieldtoresolve not in infieldtypebyname:
                parser.error("Undefined infield in: {},"
                             " choose from fields specified in"
                             " urspec.".format(' '.join(resolvspec)))
                if (resolutionintypes[fieldnum]
                    != infieldtypebyname[fieldtoresolve]):
                    parser.error("Field type {} in urspec of {} does not"
                                 " match type requirement {} of supplied"
                                 " resolvspec: {}".format(
                                     infieldtypebyname[fieldtoresolve],
                                     fieldtoresolve,
                                     resolutionintypes[fieldnum],
                                     ' '.join(resolvspec)))

        validatedresolvspecs.append((fieldstoresolve, resolution, outfield))
        outfields.append((outfield, typesbyresolution[resolution][1]))

    args.validatedresolvspecs = validatedresolvspecs
    args.outfields = outfields
    del args.resolvspecs

    return args


def urspecaddresolvedfields(urformat, outfields):
    """Add resolved fields from _outfields_ to _urformat_."""
    return ','.join([urformat, ','.join(' '.join([ftype[0], fname])
                                        for fname, ftype
                                        in outfields)])


def amendflows(args, resolver):
    """Read flow data, add resolved fields and send amended flow data."""
    trap = pytrap.TrapCtx()
    trap.init(sys.argv, 1, 1)

    urinput = pytrap.UnirecTemplate(args.urformat)

    # this module accepts all Unirec fieds -> set required format:
    trap.setRequiredFmt(0, pytrap.FMT_UNIREC, args.urformat)

    trap.ifcctl(0, False, pytrap.CTL_BUFFERSWITCH, 0)

    uroutformat = urspecaddresolvedfields(args.urformat, args.outfields)
    uroutput = pytrap.UnirecTemplate(uroutformat)
    trap.setDataFmt(0, pytrap.FMT_UNIREC, uroutformat)
    if args.verbose:
        print("Set output format to '{}'."
              "\nWaiting for events.".format(uroutformat))
    while True:
        # Read data from input interface
        try:
            indata = trap.recv()
            if args.verbose:
                sys.stdout.write('.')
        except pytrap.FormatMismatch:
            print("Error: input and output interfaces data format"
                  " or data specifier mismatch")
            break
        except pytrap.FormatChanged as err:
            # Get data format from negotiation, amend it, and set it
            # for output iface
            fmttype, fmtspec = trap.getDataFmt(0)  # pylint:disable=unused-variable
            # Update Unirec templates
            urinput = pytrap.UnirecTemplate(fmtspec)
            uroutformat = urspecaddresolvedfields(fmtspec, args.outfields)
            uroutput = pytrap.UnirecTemplate(uroutformat)
            trap.setDataFmt(0, pytrap.FMT_UNIREC, uroutformat)
            if args.verbose:
                print("Reset output format to '{}'.".format(uroutformat))

            # Store data from the exception
            indata = err.data  # pylint:disable=no-member
        except pytrap.Terminated:
            print("Terminated trap.")
            break
        except pytrap.TrapError:
            break

        # Check for "end-of-stream" record
        if len(indata) <= 1:
            break

        # Set indata for access using attributes
        urinput.setData(indata)
        inputvarlensize = urinput.recVarlenSize()

        # Copy flow info from indata to outdata
        resolvedvarlenmaxsize = sum(ftype[1]
                                    for fname, ftype in args.outfields
                                    if len(ftype) > 1)
        outdata = uroutput.createMessage(inputvarlensize
                                         + resolvedvarlenmaxsize)
        uroutput.setData(outdata)

        for attr, value in urinput:
            setattr(uroutput, attr, value)

        for fieldstoresolve, resolution, outfield in args.validatedresolvspecs:
            setattr(uroutput, outfield,
                    getattr(resolver, resolution)(urinput,
                                                  *fieldstoresolve))

        try:
            trap.send(outdata)
        except pytrap.Terminated:
            print("Terminated trap.")
            break
        if args.verbose:
            sys.stdout.write(',')

    trap.sendFlush()


def main(programname, *programargs):  # pylint:disable=unused-argument
    """Dispatch to parseargs and amendflows."""
    resolver = Resolver()
    args = parseargs(list(programargs), resolver)
    amendflows(args, resolver)


if __name__ == '__main__':
    sys.exit(main(*sys.argv))
