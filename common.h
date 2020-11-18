#pragma once

///
///
///

#include <iostream>
#include <stdio.h>
#include <functional>

#if __cplusplus > 201103L

using std::make_unique;

#else

/// Copied from Herb Sutter's blog (https://herbsutter.com/gotw/_102/)
template<typename T, typename... Args>
std::unique_ptr<T> make_unique(Args &&... args) {
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

#endif

template <typename T>
struct Callback;

template <typename Ret, typename... Params>
struct Callback<Ret(Params...)> {
   template <typename... Args> 
   static Ret callback(Args... args) {                    
      return func(args...);  
   }
   static std::function<Ret(Params...)> func; 
};

template <typename Ret, typename... Params>
std::function<Ret(Params...)> Callback<Ret(Params...)>::func;
