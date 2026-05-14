# gh_audit/utils/parallel_processor.py
"""Asynchronous parallel repository scanner with semaphore control."""

import asyncio
import logging
from typing import List, Any, Callable, Coroutine, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial

logger = logging.getLogger(__name__)


class ParallelProcessor:
    """Process multiple repositories in parallel with concurrency control."""
    
    def __init__(self, max_concurrent: int = 5, verbose: bool = False):
        """Initialize parallel processor.
        
        Args:
            max_concurrent: Maximum number of concurrent operations
            verbose: Enable verbose logging
        """
        self.max_concurrent = max_concurrent
        self.verbose = verbose
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._stats = {
            "total_tasks": 0,
            "completed": 0,
            "failed": 0,
            "successful": 0
        }
    
    async def process(
        self,
        tasks: List[Coroutine],
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> List[Any]:
        """Process a list of coroutines with concurrency control.
        
        Args:
            tasks: List of coroutine objects to execute
            progress_callback: Optional callback function(completed, total)
            
        Returns:
            List of results in the same order as input tasks
        """
        self._stats["total_tasks"] = len(tasks)
        self._stats["completed"] = 0
        self._stats["failed"] = 0
        self._stats["successful"] = 0
        
        results = [None] * len(tasks)
        
        async def run_task(index: int, coro: Coroutine):
            """Run a single task with semaphore control."""
            async with self._semaphore:
                try:
                    if self.verbose:
                        logger.debug(f"Starting task {index + 1}/{len(tasks)}")
                    
                    result = await coro
                    results[index] = result
                    
                    self._stats["successful"] += 1
                    if self.verbose:
                        logger.debug(f"Completed task {index + 1}/{len(tasks)}")
                    
                    return True
                    
                except Exception as e:
                    self._stats["failed"] += 1
                    logger.error(f"Task {index + 1} failed: {str(e)}")
                    results[index] = None
                    return False
                    
                finally:
                    self._stats["completed"] += 1
                    if progress_callback:
                        progress_callback(self._stats["completed"], len(tasks))
        
        # Create all tasks
        async_tasks = [
            run_task(i, coro)
            for i, coro in enumerate(tasks)
        ]
        
        # Execute all tasks concurrently
        await asyncio.gather(*async_tasks, return_exceptions=True)
        
        if self.verbose:
            logger.info(
                f"Parallel processing complete: "
                f"{self._stats['successful']}/{self._stats['total_tasks']} successful, "
                f"{self._stats['failed']} failed"
            )
        
        return results
    
    async def process_with_retry(
        self,
        task_factory: Callable[[Any], Coroutine],
        items: List[Any],
        max_retries: int = 3,
        retry_delay: float = 1.0
    ) -> List[Any]:
        """Process items with automatic retry on failure.
        
        Args:
            task_factory: Function that creates a coroutine from an item
            items: List of items to process
            max_retries: Maximum number of retry attempts
            retry_delay: Delay between retries in seconds
            
        Returns:
            List of results (None for items that failed after all retries)
        """
        results = [None] * len(items)
        pending = list(enumerate(items))
        
        for attempt in range(max_retries):
            if not pending:
                break
            
            if self.verbose and attempt > 0:
                logger.info(f"Retry attempt {attempt + 1}/{max_retries} for {len(pending)} items")
            
            current_pending = pending
            pending = []
            
            tasks = []
            for idx, item in current_pending:
                tasks.append(task_factory(item))
            
            # Process current batch
            batch_results = await self.process(tasks)
            
            # Check results
            for (idx, item), result in zip(current_pending, batch_results):
                if result is not None:
                    results[idx] = result
                else:
                    if attempt < max_retries - 1:
                        if self.verbose:
                            logger.debug(f"Will retry item {idx} (attempt {attempt + 2}/{max_retries})")
                        pending.append((idx, item))
                        await asyncio.sleep(retry_delay * (attempt + 1))
                    else:
                        logger.error(f"Failed to process item {idx} after {max_retries} attempts")
            
            if self.verbose:
                logger.info(f"Attempt {attempt + 1}: {len(results) - len(pending)} succeeded, {len(pending)} pending")
        
        return results
    
    def process_sync(
        self,
        func: Callable,
        items: List[Any],
        max_workers: Optional[int] = None
    ) -> List[Any]:
        """Process items synchronously using ThreadPoolExecutor.
        
        Args:
            func: Function to apply to each item
            items: List of items to process
            max_workers: Maximum number of worker threads
            
        Returns:
            List of results in the same order as input items
        """
        workers = max_workers or self.max_concurrent
        
        results = [None] * len(items)
        
        with ThreadPoolExecutor(max_workers=workers) as executor:
            # Submit all tasks
            future_to_index = {
                executor.submit(func, item): idx
                for idx, item in enumerate(items)
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_index):
                idx = future_to_index[future]
                try:
                    results[idx] = future.result()
                    self._stats["successful"] += 1
                except Exception as e:
                    results[idx] = None
                    self._stats["failed"] += 1
                    logger.error(f"Task {idx} failed: {str(e)}")
                
                self._stats["completed"] += 1
        
        if self.verbose:
            logger.info(
                f"Sync processing complete: "
                f"{self._stats['successful']}/{len(items)} successful"
            )
        
        return results
    
    def get_stats(self) -> dict:
        """Get processing statistics.
        
        Returns:
            Dictionary with processing statistics
        """
        return self._stats.copy()
    
    def reset_stats(self) -> None:
        """Reset processing statistics."""
        self._stats = {
            "total_tasks": 0,
            "completed": 0,
            "failed": 0,
            "successful": 0
        }


class BatchProcessor:
    """Process items in batches to avoid overwhelming APIs."""
    
    def __init__(self, batch_size: int = 10, delay_between_batches: float = 0.5):
        """Initialize batch processor.
        
        Args:
            batch_size: Number of items per batch
            delay_between_batches: Delay between batches in seconds
        """
        self.batch_size = batch_size
        self.delay_between_batches = delay_between_batches
    
    async def process_batches(
        self,
        task_factory: Callable[[Any], Coroutine],
        items: List[Any]
    ) -> List[Any]:
        """Process items in batches.
        
        Args:
            task_factory: Function that creates a coroutine from an item
            items: List of items to process
            
        Returns:
            List of results in the same order as input items
        """
        results = []
        
        for i in range(0, len(items), self.batch_size):
            batch = items[i:i + self.batch_size]
            
            if i > 0 and self.delay_between_batches > 0:
                await asyncio.sleep(self.delay_between_batches)
            
            # Create tasks for current batch
            tasks = [task_factory(item) for item in batch]
            
            # Execute batch
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results (convert exceptions to None)
            for result in batch_results:
                if isinstance(result, Exception):
                    logger.error(f"Batch processing error: {result}")
                    results.append(None)
                else:
                    results.append(result)
        
        return results


def parallel_map(
    func: Callable,
    items: List[Any],
    max_workers: int = 5,
    verbose: bool = False
) -> List[Any]:
    """Convenience function for parallel mapping.
    
    Args:
        func: Function to apply to each item
        items: List of items to process
        max_workers: Maximum number of worker threads
        verbose: Enable verbose output
        
    Returns:
        List of results
    """
    processor = ParallelProcessor(max_concurrent=max_workers, verbose=verbose)
    return processor.process_sync(func, items, max_workers=max_workers)