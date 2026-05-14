"""Parallel processing utilities for concurrent scanning."""

import asyncio
import aiohttp
from typing import List, Callable, Any, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
import logging
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

logger = logging.getLogger(__name__)


class ParallelProcessor:
    """Handle parallel execution of scanning tasks."""
    
    def __init__(self, max_workers: int = 5):
        """
        Initialize parallel processor.
        
        Args:
            max_workers: Maximum number of concurrent workers
        """
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
    
    def process_items(
        self,
        items: List[Any],
        process_func: Callable,
        description: str = "Processing",
        show_progress: bool = True
    ) -> List[Any]:
        """
        Process items in parallel.
        
        Args:
            items: List of items to process
            process_func: Function to apply to each item
            description: Progress bar description
            show_progress: Whether to show progress bar
            
        Returns:
            List of results
        """
        results = []
        
        if show_progress:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeRemainingColumn(),
            ) as progress:
                task = progress.add_task(description, total=len(items))
                
                futures = {self.executor.submit(process_func, item): item for item in items}
                
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            results.append(result)
                    except Exception as e:
                        logger.error(f"Error processing item: {e}")
                    finally:
                        progress.update(task, advance=1)
        else:
            futures = {self.executor.submit(process_func, item): item for item in items}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    logger.error(f"Error processing item: {e}")
        
        return results
    
    async def process_items_async(
        self,
        items: List[Any],
        process_func: Callable,
        description: str = "Processing"
    ) -> List[Any]:
        """
        Process items asynchronously.
        
        Args:
            items: List of items to process
            process_func: Async function to apply to each item
            description: Progress bar description
            
        Returns:
            List of results
        """
        results = []
        
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
        ) as progress:
            task = progress.add_task(description, total=len(items))
            
            semaphore = asyncio.Semaphore(self.max_workers)
            
            async def process_with_semaphore(item):
                async with semaphore:
                    return await process_func(item)
            
            tasks = [process_with_semaphore(item) for item in items]
            
            for coro in asyncio.as_completed(tasks):
                try:
                    result = await coro
                    if result:
                        results.append(result)
                except Exception as e:
                    logger.error(f"Error processing item: {e}")
                finally:
                    progress.update(task, advance=1)
        
        return results
    
    def shutdown(self):
        """Shutdown the executor."""
        self.executor.shutdown(wait=True)