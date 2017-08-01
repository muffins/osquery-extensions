/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

 #include <chrono>
 #include <thread>

#include <boost/filesystem.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/sdk.h>
#include <osquery/sql.h>

#include "osquery/filesystem/fileops.h"

using namespace osquery;

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

const std::string kRevoObfuscationDir {"osquery-revoke-obfuscation"};
const std::string kRevoObfuscationPrefix {"osquery-rvo-"};
const std::string kRevoObfuscationCmd {"C:\\Users\\Nick\\Desktop\\run-rvo.ps1"};

class RevokeObfuscationTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const override {
    return {
        std::make_tuple("script_hash", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("script_source", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("script_content", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("obfuscated", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("obfuscated_score", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("check_time", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("measure_time", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("is_whitelisted", TEXT_TYPE, ColumnOptions::DEFAULT),
    };
  }

  std::string getLatestRvoResults(const fs::path& rvoPath) {
    if(!fs::is_directory(rvoPath)) {
      return "";
    }
    std::map<unsigned int, std::string, std::greater<unsigned int>> paths;
    for(const auto& entry : boost::make_iterator_range(fs::directory_iterator(rvoPath), {})) {
      auto t = static_cast<unsigned int>(fs::last_write_time(entry));
      paths[t] = entry.path().string();
    }
    return paths.begin()->second;
  }

  QueryData generate(QueryContext& request) override {
    QueryData results;

    // TODO: Let's have this happen via a CreateProcess call
    auto cmd = "start powershell.exe " + kRevoObfuscationCmd;
    //system(cmd.c_str());

    auto latestPath = getLatestRvoResults(fs::temp_directory_path() / kRevoObfuscationDir);
    PlatformFile pFile(latestPath, PF_OPEN_EXISTING | PF_READ);
    if (!pFile.isValid()) {
      VLOG(1) << "Revo Path was not valid: " << latestPath;
      return results;
    }

    pt::ptree pt;
    pt::read_json(latestPath, pt);

    for (const auto& node : pt) {
      Row r;
      r["script_hash"] = node.second.get<std::string>("Hash");
      r["script_source"] = node.second.get<std::string>("Source");
      r["script_content"] = node.second.get<std::string>("ScriptContent");
      r["obfuscated"] = node.second.get<std::string>("Obfuscated");
      r["obfuscated_score"] = node.second.get<std::string>("ObfuscatedScore");
      r["check_time"] = node.second.get<std::string>("CheckTime.Ticks");
      r["measure_time"] = node.second.get<std::string>("MeasureTime.Ticks");
      r["is_whitelisted"] = node.second.get<std::string>("Whitelisted");
      results.push_back(r);
    }
    return results;
  }
};

REGISTER_EXTERNAL(RevokeObfuscationTablePlugin, "table", "revoke_obfuscation");

int main(int argc, char* argv[]) {
  ::Initializer runner(argc, argv, ToolType::EXTENSION);

  auto status = startExtension("revoke_obfuscation", "0.0.1");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    runner.requestShutdown(status.getCode());
  }

  runner.waitForShutdown();
  return 0;
}
