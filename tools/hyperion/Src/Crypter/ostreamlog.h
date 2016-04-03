#ifndef OSTREAMLOG_H_INCLUDED
#define OSTREAMLOG_H_INCLUDED

#include <iostream>

namespace hyperion{

    class OstreamLog{
        public:
            OstreamLog(bool v);
            OstreamLog& operator<< (std::ostream& (*pf)(std::ostream&));
            OstreamLog& operator<< (std::ios_base& (*pf)(std::ios_base&));
            OstreamLog& operator<< (const char* x);
            OstreamLog& operator<< (unsigned long val);
        private:
            bool verbose;
    };

}

#endif // OSTREAMLOG_H_INCLUDED
