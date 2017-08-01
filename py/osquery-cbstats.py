import osquery
import subprocess
import socket
import os
"""
osquery> .timer on
osquery> select count(1) from cbstats;
+----------+
| count(1) |
+----------+
| 275      |
+----------+
Run Time: real 14.114 user 0.001000 sys 0.000000
"""

# Update metrics to poll the cbstats data you care about.
# The topics can be listed with /usr/share/cb/cbstats -L
metrics = "SensorUpload,CPU,DatastoreSolrClient,DiskIO," \
          "cb-datastore_jvm_gc-incr,SensorPending,SensorUpload," \
          "VirtualMem,NetworkIO,cb-rabbitmq_management"


@osquery.register_plugin
class CbStatsPlugin(osquery.TablePlugin):

    def name(self):
        return "cbstats"

    def columns(self):
        return [
            osquery.TableColumn(name="host", type=osquery.STRING),
            osquery.TableColumn(name="topic", type=osquery.STRING),
            osquery.TableColumn(name="metric", type=osquery.STRING),
            osquery.TableColumn(name="value", type=osquery.STRING),
        ]

    def generate(self, context):

        # Subprocess out the cbstats command
        command = "/usr/share/cb/cbstats"
        args = "--metrics=" + metrics
        query_data = []
        host_name = socket.gethostname()

        if(not os.path.exists(command)):
            return query_data
        try:
            p = subprocess.Popen([command, args], stdout=subprocess.PIPE)
            resp = p.communicate()[0]
        except Exception as _e:
            return query_data

        for line in resp.split("\n"):
            if(line == '' or len(line.split('.')) < 2):
                continue
            row = {}
            _tmp, val = line.split(":")
            top, met = _tmp.split(".")[0], _tmp.split(".")[1]
            row["host"] = host_name
            row["topic"] = top
            row["metric"] = met
            row["value"] = val.strip()
            query_data.append(row)

        return query_data

if __name__ == "__main__":
    osquery.start_extension(name="cbstats",
                            version="0.0.2",)
