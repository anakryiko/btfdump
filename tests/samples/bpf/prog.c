struct pt_regs {
  long arg1;
  long arg2;
};

struct sk_buff {
  int i;
  struct net_device *dev;
};

static int (*bpf_probe_read)(void *dst, int size, void *unsafe_ptr) =
        (void *) 4;

extern unsigned __kernel_version;

int bpf_prog(struct pt_regs *ctx) {
  struct net_device *dev = 0;

  // ctx->arg* does not need bpf_probe_read
  if (__kernel_version >= 41608)
    bpf_probe_read(&dev, sizeof(dev), &((struct sk_buff *)ctx->arg1)->dev);
  else
    bpf_probe_read(&dev, sizeof(dev), &((struct sk_buff *)ctx->arg2)->dev);
  return dev != 0;
}

