#include <memory>
#include "CPFCtl.h"

int main(int argc, char *argv[])
{
  std::unique_ptr<CPFCtl> mProcess(new CPFCtl);

  return 0;
}
