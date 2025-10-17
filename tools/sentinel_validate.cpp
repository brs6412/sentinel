#include <fstream>
#include <iostream>
#include <regex>
#include <string>
#include <vector>

static bool is_blank(const std::string& s){return s.find_first_not_of(" \t\r\n")==std::string::npos;}
static bool json_kv(const std::string& line, const char* k){ return std::regex_search(line,std::regex(std::string("\"")+k+"\"\\s*:\\s*\"")); }

static int validate_endpoints(const std::string& path){
  std::ifstream in(path); if(!in.good()){ std::cerr<<"cannot open "<<path<<"\n"; return 2; }
  std::string line; int n=0;
  while(std::getline(in,line)){
    if(is_blank(line)) continue;
    ++n;
    if(!(json_kv(line,"method") && json_kv(line,"url") && json_kv(line,"name"))){
      std::cerr<<"bad endpoints jsonl line "<<n<<"\n"; return 1;
    }
  }
  return 0;
}

static int validate_findings(const std::string& path){
  std::ifstream in(path); if(!in.good()){ std::cerr<<"cannot open "<<path<<"\n"; return 2; }
  std::string line; int n=0;
  while(std::getline(in,line)){
    if(is_blank(line)) continue;
    ++n;
    if(!(json_kv(line,"vuln_type") && json_kv(line,"target") && json_kv(line,"response_snippet"))){
      std::cerr<<"bad findings jsonl line "<<n<<"\n"; return 1;
    }
  }
  return 0;
}

int main(int argc, char** argv){
  if(argc<3){ std::cerr<<"usage: sentinel-validate --file PATH --type endpoints|findings\n"; return 2; }
  std::string file, type;
  for(int i=1;i+1<argc;++i){
    std::string k=argv[i], v=argv[i+1];
    if(k=="--file") file=v;
    if(k=="--type") type=v;
  }
  if(type=="endpoints") return validate_endpoints(file);
  if(type=="findings")  return validate_findings(file);
  std::cerr<<"unknown type\n"; return 2;
}
