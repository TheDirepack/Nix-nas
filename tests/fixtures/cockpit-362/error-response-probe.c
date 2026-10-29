#include <stdio.h>
#include <string.h>

#include "cockpithash.h"
#include "cockpitwebresponse.h"

static void
response_done (CockpitWebResponse *response,
               gboolean reusable,
               gpointer data)
{
  *(gboolean *)data = TRUE;
}

int
main (int argc, char **argv)
{
  g_assert_cmpint (argc, ==, 6);
  g_autoptr(GInputStream) input = g_memory_input_stream_new ();
  g_autoptr(GOutputStream) output = g_memory_output_stream_new_resizable ();
  g_autoptr(GIOStream) io = g_simple_io_stream_new (input, output);
  g_autoptr(CockpitWebResponse) response = cockpit_web_response_new (
    io, "/console/missing.html", "/missing.html", NULL, argv[1], "https");
  g_autoptr(GHashTable) headers = NULL;
  g_autoptr(GBytes) body = NULL;
  gboolean done = FALSE;

  if (!g_str_equal (argv[3], "none") || g_str_equal (argv[5], "json"))
    {
      headers = g_hash_table_new_full (cockpit_str_case_hash, cockpit_str_case_equal, g_free, g_free);
      g_hash_table_insert (headers, g_strdup ("Cache-Control"), g_strdup ("no-store"));
    }
  if (g_str_equal (argv[3], "strict") || g_str_equal (argv[3], "lower-strict"))
    g_hash_table_insert (headers,
                        g_strdup (g_str_equal (argv[3], "strict") ? "Content-Security-Policy" : "content-security-policy"),
                        g_strdup ("default-src 'none'; frame-ancestors 'none'"));
  if (g_str_equal (argv[5], "json"))
    {
      body = g_bytes_new_static ("{\"problem\":\"not-found\"}", 23);
      g_hash_table_insert (headers, g_strdup ("Content-Type"), g_strdup ("application/json"));
    }

  g_signal_connect (response, "done", G_CALLBACK (response_done), &done);
  cockpit_web_response_error_with_body (response, (guint)g_ascii_strtoull (argv[2], NULL, 10),
                                        argv[4], headers, body);
  while (!done)
    g_main_context_iteration (NULL, TRUE);

  GMemoryOutputStream *memory = G_MEMORY_OUTPUT_STREAM (output);
  gsize size = g_memory_output_stream_get_data_size (memory);
  g_assert_cmpuint (fwrite (g_memory_output_stream_get_data (memory), 1, size, stdout), ==, size);
  return 0;
}
