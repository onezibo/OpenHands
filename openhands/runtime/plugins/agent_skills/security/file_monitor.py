"""文件系统监控器

基于inotify的实时文件系统监控，专门用于监控AFL++crashes目录和其他安全分析文件变化。
避免SecurityAgent频繁轮询检查文件，减少循环检测风险。
"""

import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

try:
    import inotify_simple

    INOTIFY_AVAILABLE = True
except ImportError:
    INOTIFY_AVAILABLE = False

from openhands.core.logger import openhands_logger as logger


class FileEventType(Enum):
    """文件事件类型"""

    CREATED = 'created'  # 文件创建
    MODIFIED = 'modified'  # 文件修改
    DELETED = 'deleted'  # 文件删除
    MOVED = 'moved'  # 文件移动


@dataclass
class FileEvent:
    """文件事件"""

    event_type: FileEventType
    file_path: Path
    timestamp: float
    size: Optional[int] = None
    is_directory: bool = False


class FileSystemMonitor:
    """文件系统监控器

    使用inotify（Linux）或轮询（fallback）监控文件系统变化。
    专门优化用于SecurityAgent的AFL++崩溃文件监控。
    """

    def __init__(self, use_polling: bool = False, poll_interval: int = 5):
        """初始化文件系统监控器

        Args:
            use_polling: 强制使用轮询模式（忽略inotify）
            poll_interval: 轮询间隔（秒）
        """
        self.use_polling = use_polling or not INOTIFY_AVAILABLE
        self.poll_interval = poll_interval

        # 监控状态
        self._monitoring = False
        self._stop_event = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None

        # inotify相关
        self._inotify = None
        self._watch_descriptors: dict[str, int] = {}

        # 轮询相关
        self._polling_paths: dict[str, set[Path]] = {}
        self._last_states: dict[str, dict[Path, float]] = {}

        # 事件处理
        self._event_handlers: dict[str, list[Callable[[FileEvent], None]]] = {}
        self._event_lock = threading.Lock()

        if self.use_polling:
            logger.info('文件监控器使用轮询模式')
        else:
            logger.info('文件监控器使用inotify模式')

    def add_watch(
        self,
        path: str,
        event_handler: Callable[[FileEvent], None],
        watch_key: str = None,
        recursive: bool = False,
    ) -> bool:
        """添加监控路径

        Args:
            path: 要监控的路径
            event_handler: 事件处理函数
            watch_key: 监控键名（用于标识和移除）
            recursive: 是否递归监控子目录

        Returns:
            bool: 添加是否成功
        """
        path = Path(path)
        if not path.exists():
            logger.warning(f'监控路径不存在: {path}')
            return False

        watch_key = watch_key or str(path)

        try:
            with self._event_lock:
                # 添加事件处理器
                if watch_key not in self._event_handlers:
                    self._event_handlers[watch_key] = []
                self._event_handlers[watch_key].append(event_handler)

                if self.use_polling:
                    # 轮询模式
                    if watch_key not in self._polling_paths:
                        self._polling_paths[watch_key] = set()
                        self._last_states[watch_key] = {}

                    # 添加监控路径
                    if path.is_dir():
                        self._polling_paths[watch_key].add(path)
                        if recursive:
                            for subpath in path.rglob('*'):
                                if subpath.is_dir():
                                    self._polling_paths[watch_key].add(subpath)
                    else:
                        self._polling_paths[watch_key].add(path.parent)

                    # 初始化状态
                    self._update_polling_state(watch_key)

                else:
                    # inotify模式
                    if not self._inotify:
                        self._inotify = inotify_simple.INotify()

                    # 设置监控标志
                    flags = (
                        inotify_simple.flags.CREATE
                        | inotify_simple.flags.MODIFY
                        | inotify_simple.flags.DELETE
                        | inotify_simple.flags.MOVED_TO
                        | inotify_simple.flags.MOVED_FROM
                    )

                    if path.is_dir():
                        wd = self._inotify.add_watch(str(path), flags)
                        self._watch_descriptors[watch_key] = wd

                        if recursive:
                            for subpath in path.rglob('*'):
                                if subpath.is_dir():
                                    sub_key = f'{watch_key}_{subpath.relative_to(path)}'
                                    sub_wd = self._inotify.add_watch(
                                        str(subpath), flags
                                    )
                                    self._watch_descriptors[sub_key] = sub_wd
                    else:
                        # 监控文件的父目录
                        wd = self._inotify.add_watch(str(path.parent), flags)
                        self._watch_descriptors[watch_key] = wd

            logger.info(
                f'添加文件监控: {path} (键: {watch_key}, 模式: {"轮询" if self.use_polling else "inotify"})'
            )
            return True

        except Exception as e:
            logger.error(f'添加文件监控失败: {e}')
            return False

    def remove_watch(self, watch_key: str) -> bool:
        """移除监控

        Args:
            watch_key: 监控键名

        Returns:
            bool: 移除是否成功
        """
        try:
            with self._event_lock:
                # 移除事件处理器
                if watch_key in self._event_handlers:
                    del self._event_handlers[watch_key]

                if self.use_polling:
                    # 轮询模式
                    if watch_key in self._polling_paths:
                        del self._polling_paths[watch_key]
                    if watch_key in self._last_states:
                        del self._last_states[watch_key]
                else:
                    # inotify模式
                    if watch_key in self._watch_descriptors:
                        if self._inotify:
                            self._inotify.rm_watch(self._watch_descriptors[watch_key])
                        del self._watch_descriptors[watch_key]

                    # 移除递归监控的子目录
                    keys_to_remove = [
                        k
                        for k in self._watch_descriptors.keys()
                        if k.startswith(f'{watch_key}_')
                    ]
                    for key in keys_to_remove:
                        if self._inotify:
                            self._inotify.rm_watch(self._watch_descriptors[key])
                        del self._watch_descriptors[key]

            logger.info(f'移除文件监控: {watch_key}')
            return True

        except Exception as e:
            logger.error(f'移除文件监控失败: {e}')
            return False

    def start_monitoring(self) -> bool:
        """开始监控"""
        if self._monitoring:
            logger.warning('文件监控器已在运行中')
            return False

        try:
            self._monitoring = True
            self._stop_event.clear()

            if self.use_polling:
                self._monitor_thread = threading.Thread(
                    target=self._polling_loop, daemon=True
                )
            else:
                self._monitor_thread = threading.Thread(
                    target=self._inotify_loop, daemon=True
                )

            self._monitor_thread.start()
            logger.info('文件监控器启动成功')
            return True

        except Exception as e:
            logger.error(f'启动文件监控器失败: {e}')
            self._monitoring = False
            return False

    def stop_monitoring(self) -> bool:
        """停止监控"""
        if not self._monitoring:
            return True

        try:
            self._monitoring = False
            self._stop_event.set()

            if self._monitor_thread and self._monitor_thread.is_alive():
                self._monitor_thread.join(timeout=5)

            # 清理inotify资源
            if self._inotify:
                self._inotify.close()
                self._inotify = None

            logger.info('文件监控器已停止')
            return True

        except Exception as e:
            logger.error(f'停止文件监控器失败: {e}')
            return False

    def _polling_loop(self):
        """轮询监控循环"""
        logger.info('开始轮询文件监控...')

        while not self._stop_event.is_set():
            try:
                with self._event_lock:
                    for watch_key in list(self._polling_paths.keys()):
                        self._check_polling_changes(watch_key)

                # 等待下一次检查
                self._stop_event.wait(self.poll_interval)

            except Exception as e:
                logger.error(f'轮询监控出错: {e}')
                time.sleep(1)

        logger.info('轮询文件监控结束')

    def _inotify_loop(self):
        """inotify监控循环"""
        if not self._inotify:
            logger.error('inotify未初始化')
            return

        logger.info('开始inotify文件监控...')

        while not self._stop_event.is_set():
            try:
                # 设置较短的超时，以便能够响应停止信号
                events = self._inotify.read(timeout=1000)  # 1秒超时

                for event in events:
                    self._handle_inotify_event(event)

            except Exception as e:
                if 'timeout' not in str(e).lower():
                    logger.error(f'inotify监控出错: {e}')
                    time.sleep(1)

        logger.info('inotify文件监控结束')

    def _update_polling_state(self, watch_key: str):
        """更新轮询状态"""
        if watch_key not in self._polling_paths:
            return

        current_state = {}

        for path in self._polling_paths[watch_key]:
            if path.exists():
                try:
                    for file_path in path.iterdir():
                        if file_path.is_file():
                            stat = file_path.stat()
                            current_state[file_path] = stat.st_mtime
                except OSError:
                    pass

        self._last_states[watch_key] = current_state

    def _check_polling_changes(self, watch_key: str):
        """检查轮询变化"""
        if watch_key not in self._polling_paths:
            return

        old_state = self._last_states.get(watch_key, {})
        current_state = {}

        # 收集当前状态
        for path in self._polling_paths[watch_key]:
            if path.exists():
                try:
                    for file_path in path.iterdir():
                        if file_path.is_file():
                            stat = file_path.stat()
                            current_state[file_path] = stat.st_mtime
                except OSError:
                    continue

        # 检查新增文件
        for file_path, mtime in current_state.items():
            if file_path not in old_state:
                # 新文件
                self._emit_event(
                    watch_key,
                    FileEvent(
                        event_type=FileEventType.CREATED,
                        file_path=file_path,
                        timestamp=time.time(),
                        size=file_path.stat().st_size if file_path.exists() else None,
                    ),
                )
            elif old_state[file_path] != mtime:
                # 修改的文件
                self._emit_event(
                    watch_key,
                    FileEvent(
                        event_type=FileEventType.MODIFIED,
                        file_path=file_path,
                        timestamp=time.time(),
                        size=file_path.stat().st_size if file_path.exists() else None,
                    ),
                )

        # 检查删除的文件
        for file_path in old_state:
            if file_path not in current_state:
                self._emit_event(
                    watch_key,
                    FileEvent(
                        event_type=FileEventType.DELETED,
                        file_path=file_path,
                        timestamp=time.time(),
                    ),
                )

        # 更新状态
        self._last_states[watch_key] = current_state

    def _handle_inotify_event(self, event):
        """处理inotify事件"""
        try:
            event_path = (
                Path(event.path) / event.name if event.name else Path(event.path)
            )

            # 确定事件类型
            if event.mask & inotify_simple.flags.CREATE:
                event_type = FileEventType.CREATED
            elif event.mask & inotify_simple.flags.MODIFY:
                event_type = FileEventType.MODIFIED
            elif event.mask & (
                inotify_simple.flags.DELETE | inotify_simple.flags.DELETE_SELF
            ):
                event_type = FileEventType.DELETED
            elif event.mask & (
                inotify_simple.flags.MOVED_TO | inotify_simple.flags.MOVED_FROM
            ):
                event_type = FileEventType.MOVED
            else:
                return  # 忽略其他类型的事件

            # 创建文件事件
            file_event = FileEvent(
                event_type=event_type,
                file_path=event_path,
                timestamp=time.time(),
                size=event_path.stat().st_size
                if event_path.exists() and event_path.is_file()
                else None,
                is_directory=bool(event.mask & inotify_simple.flags.ISDIR),
            )

            # 找到匹配的监控键
            for watch_key, wd in self._watch_descriptors.items():
                if wd == event.wd:
                    self._emit_event(watch_key, file_event)
                    break

        except Exception as e:
            logger.error(f'处理inotify事件失败: {e}')

    def _emit_event(self, watch_key: str, event: FileEvent):
        """发出文件事件"""
        try:
            handlers = self._event_handlers.get(watch_key, [])
            for handler in handlers:
                try:
                    handler(event)
                except Exception as e:
                    logger.error(f'文件事件处理器执行失败: {e}')

        except Exception as e:
            logger.error(f'发出文件事件失败: {e}')

    def get_monitoring_status(self) -> dict[str, any]:
        """获取监控状态"""
        return {
            'monitoring': self._monitoring,
            'mode': 'polling' if self.use_polling else 'inotify',
            'poll_interval': self.poll_interval,
            'watched_paths': len(
                self._polling_paths if self.use_polling else self._watch_descriptors
            ),
            'event_handlers': len(self._event_handlers),
        }

    def __del__(self):
        """析构函数"""
        self.stop_monitoring()


class AFLCrashMonitor:
    """AFL++崩溃文件监控器

    专门用于监控AFL++的crashes目录，提供智能的崩溃文件检测。
    """

    def __init__(
        self, crashes_dir: str, on_crash_found: Callable[[list[Path]], None] = None
    ):
        """初始化AFL崩溃监控器

        Args:
            crashes_dir: AFL++的crashes目录路径
            on_crash_found: 发现崩溃时的回调函数
        """
        self.crashes_dir = Path(crashes_dir)
        self.on_crash_found = on_crash_found

        # 文件监控器
        self.file_monitor = FileSystemMonitor()
        self._crash_files: set[Path] = set()
        self._monitoring = False

        logger.info(f'初始化AFL崩溃监控器: {self.crashes_dir}')

    def start_monitoring(self) -> bool:
        """开始监控AFL崩溃文件"""
        if self._monitoring:
            return True

        try:
            # 确保crashes目录存在
            if not self.crashes_dir.exists():
                logger.warning(f'Crashes目录不存在: {self.crashes_dir}')
                self.crashes_dir.mkdir(parents=True, exist_ok=True)

            # 初始化当前崩溃文件列表
            self._update_crash_files()

            # 添加监控
            success = self.file_monitor.add_watch(
                path=str(self.crashes_dir),
                event_handler=self._handle_file_event,
                watch_key='afl_crashes',
            )

            if success:
                success = self.file_monitor.start_monitoring()

            if success:
                self._monitoring = True
                logger.info(
                    f'AFL崩溃监控启动成功，当前崩溃文件: {len(self._crash_files)}个'
                )
                return True
            else:
                logger.error('AFL崩溃监控启动失败')
                return False

        except Exception as e:
            logger.error(f'启动AFL崩溃监控失败: {e}')
            return False

    def stop_monitoring(self) -> bool:
        """停止监控"""
        if not self._monitoring:
            return True

        try:
            self.file_monitor.remove_watch('afl_crashes')
            self.file_monitor.stop_monitoring()
            self._monitoring = False
            logger.info('AFL崩溃监控已停止')
            return True

        except Exception as e:
            logger.error(f'停止AFL崩溃监控失败: {e}')
            return False

    def _handle_file_event(self, event: FileEvent):
        """处理文件事件"""
        try:
            # 只关心crashes目录中的新文件
            if (
                event.event_type == FileEventType.CREATED
                and not event.is_directory
                and str(event.file_path).startswith(str(self.crashes_dir))
            ):
                # 检查是否是崩溃文件（以id:开头，不是README文件）
                if (
                    event.file_path.name.startswith('id:')
                    and 'README' not in event.file_path.name
                ):
                    self._crash_files.add(event.file_path)
                    logger.info(f'检测到新的AFL崩溃文件: {event.file_path}')

                    # 触发回调
                    if self.on_crash_found:
                        self.on_crash_found(list(self._crash_files))

        except Exception as e:
            logger.error(f'处理AFL崩溃文件事件失败: {e}')

    def _update_crash_files(self):
        """更新崩溃文件列表"""
        self._crash_files.clear()

        if self.crashes_dir.exists():
            for crash_file in self.crashes_dir.glob('id:*'):
                if crash_file.is_file() and 'README' not in crash_file.name:
                    self._crash_files.add(crash_file)

    def get_crash_files(self) -> list[Path]:
        """获取当前崩溃文件列表"""
        return list(self._crash_files)

    def get_crash_count(self) -> int:
        """获取崩溃文件数量"""
        return len(self._crash_files)

    def __del__(self):
        """析构函数"""
        self.stop_monitoring()
