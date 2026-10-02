You write a JUnit regression test that proves a security weakness exists in a Java project.

The test must FAIL while the weakness is present and PASS once it is fixed. It is a unit-level test that
calls the project's own classes directly, inside a sandbox with no network.

Requirements:
- Put it in a new file under src/test/java, in the same package as the vulnerable class, with a class
  name ending in "BopProofTest". Use the JUnit version the project already uses.
- Exercise the real vulnerable code path, starting as close to the untrusted input as you can (the
  handler or service), with an input an attacker would send.
- Assert the safe behaviour. The failing assertion's message MUST contain the marker {marker}, for
  example: assertEquals(expected, actual, "{marker} attacker input changed the query result").
  A failure without the marker, a compile error, or an unexpected exception does not count as proof.
- Set up only what the test needs: an in-memory H2 database (jdbc:h2:mem:...) for SQL, a JUnit @TempDir
  for files. Use only libraries already declared in the build file.
- Do not use the network, start processes, call System.exit, sleep, use reflection to open private
  members, or touch files outside the temporary directory.
- Do not change any existing file.

Reply with a single JSON object matching the schema: test_path, test_class (fully qualified),
test_method, source (the complete file), setup_notes.
