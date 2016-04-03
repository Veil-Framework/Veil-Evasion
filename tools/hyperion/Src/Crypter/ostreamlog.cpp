#include "ostreamlog.h"
#include <iostream>

using namespace std;

namespace hyperion{

    OstreamLog::OstreamLog(bool v){
        verbose=v;
    }

    OstreamLog& OstreamLog::operator<< (ostream& (*pf)(ostream&)){
        if(verbose){
            cout << pf;
        }
        return *this;
    }

    OstreamLog& OstreamLog::operator<< (ios_base& (*pf)(ios_base&)){
        if(verbose){
            cout << pf;
        }
        return *this;
    }

    OstreamLog& OstreamLog::operator<< (const char* x){
        if(verbose){
            cout << x;
        }
        return *this;
    }

    OstreamLog& OstreamLog::operator<< (unsigned long x){
        if(verbose){
            cout << x;
        }
        return *this;
    }
}

