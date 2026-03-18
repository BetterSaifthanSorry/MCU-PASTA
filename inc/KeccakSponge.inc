#define JOIN0(a, b) a##b
#define JOIN(a, b) JOIN0(a, b)

#define Sponge JOIN(prefix, _Sponge)
#define SpongeInstance JOIN(prefix, _SpongeInstance)
#define SpongeInitialize JOIN(prefix, _SpongeInitialize)
#define SpongeAbsorb JOIN(prefix, _SpongeAbsorb)
#define SpongeAbsorbLastFewBits JOIN(prefix, _SpongeAbsorbLastFewBits)
#define SpongeSqueeze JOIN(prefix, _SpongeSqueeze)

#define SnP_stateSizeInBytes JOIN(SnP, _stateSizeInBytes)
#define SnP_stateAlignment JOIN(SnP, _stateAlignment)
#define SnP_StaticInitialize JOIN(SnP, _StaticInitialize)
#define SnP_Initialize JOIN(SnP, _Initialize)
#define SnP_AddByte JOIN(SnP, _AddByte)
#define SnP_AddBytes JOIN(SnP, _AddBytes)
#define SnP_ExtractBytes JOIN(SnP, _ExtractBytes)

int Sponge(unsigned int rate, unsigned int capacity, const unsigned char *input,
           size_t inputByteLen, unsigned char suffix, unsigned char *output,
           size_t outputByteLen) {
  ALIGN(SnP_stateAlignment) unsigned char state[SnP_stateSizeInBytes];
  unsigned int partialBlock;
  const unsigned char *curInput = input;
  unsigned char *curOutput = output;
  unsigned int rateInBytes = rate / 8;

  if (rate + capacity != SnP_width) return 1;
  if ((rate <= 0) || (rate > SnP_width) || ((rate % 8) != 0)) return 1;
  if (suffix == 0) return 1;

  SnP_StaticInitialize();
  SnP_Initialize(state);

  while (inputByteLen >= (size_t)rateInBytes) {
    SnP_AddBytes(state, curInput, 0, rateInBytes);
    SnP_Permute(state);
    curInput += rateInBytes;
    inputByteLen -= rateInBytes;
  }

  partialBlock = (unsigned int)inputByteLen;
  SnP_AddBytes(state, curInput, 0, partialBlock);
  SnP_AddByte(state, suffix, partialBlock);
  
  if ((suffix >= 0x80) && (partialBlock == (rateInBytes - 1)))
    SnP_Permute(state);
  SnP_AddByte(state, 0x80, rateInBytes - 1);
  SnP_Permute(state);

  while (outputByteLen > (size_t)rateInBytes) {
    SnP_ExtractBytes(state, curOutput, 0, rateInBytes);
    SnP_Permute(state);
    curOutput += rateInBytes;
    outputByteLen -= rateInBytes;
  }

  partialBlock = (unsigned int)outputByteLen;
  SnP_ExtractBytes(state, curOutput, 0, partialBlock);

  return 0;
}

int SpongeInitialize(SpongeInstance *instance, unsigned int rate,
                     unsigned int capacity) {
  if (rate + capacity != SnP_width) return 1;
  if ((rate <= 0) || (rate > SnP_width) || ((rate % 8) != 0)) return 1;
  SnP_StaticInitialize();
  SnP_Initialize(instance->state);
  instance->rate = rate;
  instance->byteIOIndex = 0;
  instance->squeezing = 0;

  return 0;
}

int SpongeAbsorb(SpongeInstance *instance, const unsigned char *data,
                 size_t dataByteLen) {
  size_t i, j;
  unsigned int partialBlock;
  const unsigned char *curData;
  unsigned int rateInBytes = instance->rate / 8;

  if (instance->squeezing) return 1; 

  i = 0;
  curData = data;
  while (i < dataByteLen) {
    if ((instance->byteIOIndex == 0) && (dataByteLen >= (i + rateInBytes))) {
        for (j = dataByteLen - i; j >= rateInBytes; j -= rateInBytes) {
          SnP_AddBytes(instance->state, curData, 0, rateInBytes);
          SnP_Permute(instance->state);
          curData += rateInBytes;
        }
        i = dataByteLen - j;
    } else {
      partialBlock = (unsigned int)(dataByteLen - i);
      if (partialBlock + instance->byteIOIndex > rateInBytes)
        partialBlock = rateInBytes - instance->byteIOIndex;
      i += partialBlock;

      SnP_AddBytes(instance->state, curData, instance->byteIOIndex, partialBlock);
      curData += partialBlock;
      instance->byteIOIndex += partialBlock;
      if (instance->byteIOIndex == rateInBytes) {
        SnP_Permute(instance->state);
        instance->byteIOIndex = 0;
      }
    }
  }
  return 0;
}

int SpongeAbsorbLastFewBits(SpongeInstance *instance,
                            unsigned char delimitedData) {
  unsigned int rateInBytes = instance->rate / 8;

  if (delimitedData == 0) return 1;
  if (instance->squeezing) return 1;

  SnP_AddByte(instance->state, delimitedData, instance->byteIOIndex);
  if ((delimitedData >= 0x80) && (instance->byteIOIndex == (rateInBytes - 1)))
    SnP_Permute(instance->state);
  SnP_AddByte(instance->state, 0x80, rateInBytes - 1);
  SnP_Permute(instance->state);
  instance->byteIOIndex = 0;
  instance->squeezing = 1;
  return 0;
}

int SpongeSqueeze(SpongeInstance *instance, unsigned char *data,
                  size_t dataByteLen) {
  size_t i, j;
  unsigned int partialBlock;
  unsigned int rateInBytes = instance->rate / 8;
  unsigned char *curData;

  if (!instance->squeezing) SpongeAbsorbLastFewBits(instance, 0x01);

  i = 0;
  curData = data;
  while (i < dataByteLen) {
    if ((instance->byteIOIndex == rateInBytes) &&
        (dataByteLen >= (i + rateInBytes))) {
      for (j = dataByteLen - i; j >= rateInBytes; j -= rateInBytes) {
        SnP_Permute(instance->state);
        SnP_ExtractBytes(instance->state, curData, 0, rateInBytes);
        curData += rateInBytes;
      }
      i = dataByteLen - j;
    } else {
      if (instance->byteIOIndex == rateInBytes) {
        SnP_Permute(instance->state);
        instance->byteIOIndex = 0;
      }
      partialBlock = (unsigned int)(dataByteLen - i);
      if (partialBlock + instance->byteIOIndex > rateInBytes)
        partialBlock = rateInBytes - instance->byteIOIndex;
      i += partialBlock;

      SnP_ExtractBytes(instance->state, curData, instance->byteIOIndex,
                       partialBlock);
      curData += partialBlock;
      instance->byteIOIndex += partialBlock;
    }
  }
  return 0;
}
#undef Sponge
#undef SpongeInstance
#undef SpongeInitialize
#undef SpongeAbsorb
#undef SpongeAbsorbLastFewBits
#undef SpongeSqueeze
#undef SnP_stateSizeInBytes
#undef SnP_stateAlignment
#undef SnP_StaticInitialize
#undef SnP_Initialize
#undef SnP_AddByte
#undef SnP_AddBytes
#undef SnP_ExtractBytes
