#ifndef UTILITY_H
#define UTILITY_H

template <typename T>
struct zallocator
{
public:
    typedef T value_type;
    typedef value_type* pointer;
    typedef const value_type* const_pointer;
    typedef value_type& reference;
    typedef const value_type& const_reference;
    typedef std::size_t size_type;
    typedef std::ptrdiff_t difference_type;

    pointer address (reference v) const {return &v;}
    const_pointer address (const_reference v) const {return &v;}

    pointer allocate (size_type n, const void* hint = 0) {
        if (n > std::numeric_limits<size_type>::max() / sizeof(T))
            throw std::bad_alloc();
        return static_cast<pointer> (::operator new (n * sizeof (value_type)));
    }

    void deallocate(pointer p, size_type n) {
        OPENSSL_cleanse(p, n*sizeof(T));
        ::operator delete(p); 
    }
    
    size_type max_size() const {
        return std::numeric_limits<size_type>::max() / sizeof (T);
    }
    
    template<typename U>
    struct rebind
    {
        typedef zallocator<U> other;
    };

    void construct (pointer ptr, const T& val) {
        new (static_cast<T*>(ptr) ) T (val);
    }

    void destroy(pointer ptr) {
        static_cast<T*>(ptr)->~T();
    }

#if __cpluplus >= 201103L
    template<typename U, typename... Args>
    void construct (U* ptr, Args&&  ... args) {
        ::new (static_cast<void*> (ptr) ) U (std::forward<Args> (args)...);
    }

    template<typename U>
    void destroy(U* ptr) {
        ptr->~U();
    }
#endif
};

typedef unsigned char byte;

void gen_params(byte *key, int keySize, byte *iv, int ivSize)
{
    int rc = RAND_bytes(key, keySize);
    if (rc != 1)
      throw std::runtime_error("RAND_bytes key failed");

    rc = RAND_bytes(iv, ivSize);
    if (rc != 1)
      throw std::runtime_error("RAND_bytes for iv failed");
}

void select_random_key(unsigned char *key, int b)
{
    int i;

    RAND_bytes(key, b);
    // for (i = 0; i < b - 1; i++)
    // {
    //     printf("%02X:", key[i]);
    // }
    // printf("%02X:\n", key[i]);
}

void select_random_iv(unsigned char *iv, int b)
{
    RAND_pseudo_bytes(iv, b);
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

#endif