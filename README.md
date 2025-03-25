# The NASA AMMOS Multi-Mission BPSec Library (BSL)

The NASA Advanced Multi-Mission Operations System [AMMOS](https://ammos.nasa.gov/) sponsored the development of a mission-agnostic implementation of Bundle Protocol Security (BPSec), as specified in IETF RFC 9172 and RFC 9173.

The BPSec Library (BSL) links at compile-time to a host Bundle Protocol Agent (BPA), and does not itself define a standalone executable. It exposes a simple interface to the host BPA for querying and applying BPSec-defined security operations on Bundles (the Protocol Data Unit of the Bundle Protocol). The BSL aspires to provide a simple API and flexible architecture readily adaptable for either resource-constrained embedded platforms or high-performance routers or ground systems.

## Background

The Internet Engineering Task Force (IETF) publication [RFC 9171 &mdash; Bundle Protocol Verstion 7](https://datatracker.ietf.org/doc/rfc9171/) defines the Bundle Protocol, a communication architecture for challenged networking environments.

The following publication [RFC 9172 &mdash; Bundle Protocol Security](https://datatracker.ietf.org/doc/rfc9172/) specifies BPSec, which details how authentication and confidentiality may be applied differentially to blocks within a bundle, accounting for varied and complex network security policies. The publication [RFC 9173 &mdash; Default Security Contexts for Bundle Protocol Security](https://datatracker.ietf.org/doc/rfc9173/) details the default security contexts for it, which captures choice of cryptographic algorithms and suitable parameters for them.

Further context and background on Delay Tolerant Networking, the Bundle Protocol, and their use in space networks:
 * [RFC 4838 &mdash; Delay Tolerant Networking Architecture](https://www.rfc-editor.org/info/rfc4838) by V. Cerf, et al.
 * [A Delay Tolerant Network Architecture for Challenged Internets](https://dl.acm.org/doi/10.1145/863955.863960) by K. Fall, et al.

## Status and Milestones 

The BSL reached a milestone achieving initial evaluation capability during Q1 2025. Once approved by program leadership, the source code will be available at this repo.

The BSL targets an initial "1.0" release during Q3-Q4 2025.

An overview of the BSL has been delivered at the [2025 Workshop on Spacecraft Flight Software](https://flightsoftware.org/workshop/FSW2025). Members of the audience may be allowed pre-release evaluation copies, please contact the presentation author.

If desired, please "star" this repository, so that you may be notified when new releases drop.

## Contact

#### NASA AMMOS Program Office at JPL

General contacts for NASA AMMOS: https://ammos.nasa.gov/contact/

 * Mission Interface Office -- ammos_info@jpl.nasa.gov

#### Johns Hopkins Applied Physics Lab (APL)

The APL team supporting this effort consists of the following.

 * Bill Van Besien (FSW Workshop Presenter) -- Bill.Van.Besien@jhuapl.edu
 * Brian Sipos -- Brian.Sipos@jhuapl.edu
 * Chris Krupiarz -- Chris.Krupiarz@jhuapl.edu
 * Sarah Heiner -- Sarah.Heiner@jhuapl.edu
 * Ed Birrane -- Ed.Birrane@jhuapl.edu

