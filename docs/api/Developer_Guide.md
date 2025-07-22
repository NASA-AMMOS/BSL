<!--
Copyright (c) 2024 The Johns Hopkins University Applied Physics
Laboratory LLC.

This file is part of the Bundle Protocol Security Library (BSL).

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This work was performed for the Jet Propulsion Laboratory, California
Institute of Technology, sponsored by the United States Government under
the prime contract 80NM0018D0004 between the Caltech and NASA under
subcontract 1700763.
-->

# Developer Guide

This page covers information for **Backend Developers**, or more specifically those who may be implementing a BPSec backend, or a new Security Context or Policy Provider.

This page contains conventions necessary for BSL developers and helpful for BSL users to understand.

# Code Conventions

## Symbol Naming

Generally, all functions should be "namespaced" with `BSL_` or a similar variant.

 * Structs should take the form of `BSL_MyStruct_t`.
 * Functions operating on structs should take the form of `BSL_MyStruct_FunctionOnStruct`.
 * All structures should provide an `_Init`, `_Deinit`, `_IsConsistent`, and `_Sizeof`.
 * Functions not operating over a context struct should use `BSL_ModuleName_Function`.

## Error checking

Generally, functions returning `int`s indicate error codes.

 * A code of `0` (`BSL_SUCCESS`) means no error.
 * A negative number ALWAYS indicates an error.
 * A positive number can be something else depending on context.

## Enums

Enums take the format of `BSL_EnumName_e` (with a typedef).

Variants of the enum should be "namespaced" with the enum, to manage clutter.

E.g., 
```
typedef enum {
  BSL_MYEXAMPLEENUM_OPTION1 = 1,
  BSL_MYEXAMPLEENUM_OPTION2
  // ...
} BSL_MyExampleEnum_e;
```

## Implementation Patterns

More notes forthcoming.

#### &raquo; Negative return codes _always_ means failure
 * Most functions that return an `int` (or a typedef over an `int`) should be interpreted as returning a status code.
 * A negative status code *always* indicates a failure. This enables simple checking for failure: `if (BSL_MyFunc(arg) &lt; 0) ...`
 * A zero indicates non-error, with a typedef `BSL_SUCCESS`.
 * A positive number may indicate a non-failure with optional supplementary data (e.g., number of bytes consumed).
 * Functions returning integers that do not indicate error codes will generally return a `size_t` or `uint64_t`.

#### &raquo; NULL is _never_* a valid argument
 * A NULL pointer for almost any function argument is considered an anomaly and a programmer-error.
 * Note the \@nullable doxygen command to indicate whenever a parameter _may_ be NULL.
 * The public front-end API is more gracious to NULL arguments (returns error code). It is considered a runtime anomaly.
 * Code further in the backend is more `assert`-ive of NULL checks. A NULL argument here is not a runtime anomaly, but rather an indication the programmer made a mistake.
 * If you are not already familiar, see the ["Billion Dollar Mistake"](https://www.infoq.com/presentations/Null-References-The-Billion-Dollar-Mistake-Tony-Hoare/).
 * \*Note: The `GetBlockMetadata` function does permit NULL arguments, as it only populates arguments that are requested.
 * \*Note: Certain functions that wrap OpenSSL functionality may also permit NULLs to be consistent with its interface.

#### &raquo; Extremely defensive coding style
 * The BPSecLib is intended for flight systems, mission-critical systems, and security-critical systems.
 * Safety and correctness are the primacy concerns.
 * Basic idea: All functions validate their context's state, and _only_ continue to execute if the state is valid. I.e., "If it's not in a proper state, it's not going to run". It is safer to crash than continue with undefined behavior.
 * All function arguments are aggressively checked. Macros help indicate argument sanity, property checks and pre/post conditions.
 * Note all structs have an `_IsConsistent()` function to check for validity of its state.
 * Allocated memory for structs must be zero at initialization time (for security and to check for accidental re-use).

#### &raquo; Preference for immutable data structures
 * Generally, once backend function produces and populates a struct, it should _not_ be modified.
 * Any operations over a struct must ensure that any pointers contained within it point to objects whose lifetime equals or exceeds its own.

#### &raquo; Caller allocates and owns memory
 * Any dynamically allocated memory should be released in the same function.
 * The caller of a function pre-allocates the memory for the called function.

#### &raquo; Maximize suitability for formal verification
 * Description

#### &raquo; Play by the rules of C99

 * The C standard library does not provide containers. Arrays is all we have, so that's what we have to work with.
 * Third party libraries providing containers may be more hassle and risk than they are worth.

#### &raquo; M\*Lib structures should not be referenced in the Frontend API
 * Keep M\*Lib usage to the BSL backend, and use standard/primative structs for frontend API. The frontend should not include any M\*Lib headers.

# Documentation

All top-level public API must have inline Doxygen comment blocks (_e.g._, `/** docs */`) preferably within the same header in which the API is declared.
For reference, Doxygen comment blocks can contain complex markup based on a large set of available [commands](https://www.doxygen.nl/manual/commands.html).

## Macro-Expanded Container Declarations

When M*LIB macros are used to declare type-safe containers, the Doxygen inspection of the macro-expanded code should be inhibited but there should also be a explicit Doxygen block to provide explanation of the purpose of the struct and a reference to the type of its contents.

An example of this is below (corresponding to @ref BSL_PolicyActionIList_t).

@verbatim
/** @struct BSL_PolocuActionIList
 * An [M-I-LIST](https://github.com/P-p-H-d/mlib/blob/master/README.md#m-i-list)
 * of ::BSL_PolicyAction_t items.
 */
/// @cond Doxygen_Suppress
M_ILIST_DEF(BSL_PolicyActionList, BSL_PolicyAction_t)
/// @endcond
@endverbatim

## Citations and References

For definitions from rfc's and other sources, `@cite [source]` in the Doxygen header.
If possible (e.g. for RFCs) include the document number in the text for convenience, as in ```RFC XXXX @cite rfcXXXX```.

# File Naming

Within the BSL source tree, all library contents are under the `src` directory and all tests are under the `test` directory.
Within the `src` directory the tree structure of all header files is the same as when the library is installed to the host filesystem.

File names follow CFE-style conventions.

The top of each file should contain a Doxygen block for the file itself, including an association with a specific module. An example of this is below.

@verbatim
/** @file
 * @ingroup frontend
 * Brief summary.
 * Detailed description follows.
 */
@endverbatim

# Symbol Naming

Symbol names follow the C99 convention of lowercase names with underscore separators.

All public API prefixed with `BSL_` to provide a virtual 'namespace' to the API.

All public API functions should follow the general `[noun]_[verb]` convention for naming.
More generally, public API functions should follow the pattern `BLS_[StructureContext]_[VerbPhraseFunctionName]`

When a set of functions are related to a struct, they should have the same noun prefix as the struct name (_e.g._, the `struct example_s` with typedef `example_t` should have corresponding functions named like `example_XYZ()`).
Beyond the common naming, functions related to a struct should be indicated using the `@memberof` Doxygen command.
An example of this is below.

@verbatim
/** Brief summary.
 * Detailed description follows.
 */
typedef struct BSL_Example_s{
  ...
} BSL_Example_t;

/** Brief summary.
 * Detailed description follows.
 * @memberof BSL_Example_t
 *
 * ... @param and @return ...
 */
int BSL_Example_DoThing(bsl_example_t *obj, ...);
@endverbatim

# Error Reporting and Handling

Functions that cannot fail should have `void` return type.
Functions that can fail should have `int` return type and use the following common values:

**Negative Values**: ALWAYS indicates failure. Specific error code can be captured by the actual value of the returned integer.
**Zero**: Means success (unless clearly indicated otherwise in exceptional use-cases)
**Positive**: Implies success, with some supplementary data. For example, a `_CreateBlock()` function, upon success, would return a positive integer containing the ID of the block just created.

NOTE!! This pattern is being adapted. A negative value indicates error, zero indicates succes.
There may be times when there may be meaningful context associated with a positive value (e.g., number of bytes written).

# Structs and Functions

Much of the public API involves state kept in a struct with associated functions to inspect and manipulate the state of that struct.

Generally, users of the API should not access struct members directly.
But specific documentation on each struct will define its specific public API.

## Initialization <name>\_Init() and <name>\_Init\_<form>()

All BSL structs must have an associated initialization function.
Members of the struct cannot be accessed before its initialization and functions called on the struct will have undefined behavior.

## De-initialization <name>\_Deinit()

All BSL structs must have an associated de-initialization function.
After its de-initialization the members of the struct will no longer have well defined state.

To help with troubleshooting, de-initialization should set pointers set to NULL and other values to a well-defined state. One option is to use `memset()` to zeroize the entire struct.

# Macros

This section contains references to commonly used macros defined for the BSL

## Memory Management Macros

When heap memory is needed at BSL runtime, the following macros are used and have the same signature and semantics as the corresponding C99 functions indicated below.

- [BSL_MALLOC](@ref BSL_MALLOC) as `malloc()`
- [BSL_REALLOC](@ref BSL_REALLOC) as `realloc()`
- [BSL_FREE](@ref BSL_FREE) as `free()`

## Error Checking Handler Macros

To help with the error reporting conventions above, the following macros can be used to simplify function precondition checking.
The precondition checks (on function parameters or on any other state generally) should be the first thing inside the function definition.

- [CHKRET(cond, val)](@ref CHKRET) for general error values
- [CHKNULL(cond)](@ref CHKNULL) when the function has a pointer return type
- [CHKERR1(cond)](@ref CHKERR1) when the function has an `int` return type
- [CHKVOID(cond)](@ref CHKVOID) when the function has an `void` return type
- [CHKFALSE(cond)](@ref CHKFALSE) when the function has an `bool` return type

# Enums

Enums with explicit values must be justified with citations, for example the declarations of @ref BSL_BundleBlockTypeCode_e.
Otherwise, they should not be given values.

Whenever possible, enums starting with zero should be avoided (since many variables default to zero, we want to avoid the case of matching an enum variant with an uninitialized, zeroed-out, value)

Enums should be `typedef`-ed with a `_e` suffix.
Enum values should be full `SCREAMING_CASE` matching the name of the struct.
@verbatim
typedef enum {
  BSL_MYENUM_OPTION1 = 1,
  BSL_MYENUM_OPTION2,
  ...
} BSL_MyEnum_e;
@endverbatim

# Unit Testing

Conventions for unit testing using the [Unity](https://github.com/ThrowTheSwitch/Unity) testing library are:

- The name of the test source file should be the same name as the unit-being-tested prefixed by `test_`.
- Where possible, name of the test functions should be the name of the function prefixed by `test_` and suffixed by the test condition, either `_valid` or `_invalid` or similar.

