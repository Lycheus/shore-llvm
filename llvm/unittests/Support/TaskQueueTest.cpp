//========- unittests/Support/TaskQueue.cpp - TaskQueue.h tests ------========//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#if LLVM_ENABLE_THREADS

#include "llvm/Support/TaskQueue.h"

#include "gtest/gtest.h"

using namespace llvm;

class TaskQueueTest : public testing::Test {
protected:
  TaskQueueTest() {}
};

TEST_F(TaskQueueTest, OrderedFutures) {
  ThreadPool TP(1);
  TaskQueue TQ(TP);
  std::atomic<int> X{ 0 };
  std::atomic<int> Y{ 0 };
  std::atomic<int> Z{ 0 };

  std::mutex M1, M2, M3;
  std::unique_lock<std::mutex> L1(M1);
  std::unique_lock<std::mutex> L2(M2);
  std::unique_lock<std::mutex> L3(M3);

  std::future<void> F1 = TQ.async([&] {
    std::unique_lock<std::mutex> Lock(M1);
    ++X;
  });
  std::future<void> F2 = TQ.async([&] {
    std::unique_lock<std::mutex> Lock(M2);
    ++Y;
  });
  std::future<void> F3 = TQ.async([&] {
    std::unique_lock<std::mutex> Lock(M3);
    ++Z;
  });

  L1.unlock();
  F1.wait();
  ASSERT_EQ(1, X);
  ASSERT_EQ(0, Y);
  ASSERT_EQ(0, Z);

  L2.unlock();
  F2.wait();
  ASSERT_EQ(1, X);
  ASSERT_EQ(1, Y);
  ASSERT_EQ(0, Z);

  L3.unlock();
  F3.wait();
  ASSERT_EQ(1, X);
  ASSERT_EQ(1, Y);
  ASSERT_EQ(1, Z);
}

TEST_F(TaskQueueTest, UnOrderedFutures) {
  ThreadPool TP(1);
  TaskQueue TQ(TP);
  std::atomic<int> X{ 0 };
  std::atomic<int> Y{ 0 };
  std::atomic<int> Z{ 0 };
  std::mutex M;

  std::unique_lock<std::mutex> Lock(M);

  std::future<void> F1 = TQ.async([&] { ++X; });
  std::future<void> F2 = TQ.async([&] { ++Y; });
  std::future<void> F3 = TQ.async([&M, &Z] {
    std::unique_lock<std::mutex> Lock(M);
    ++Z;
  });

  F2.wait();
  ASSERT_EQ(1, X);
  ASSERT_EQ(1, Y);
  ASSERT_EQ(0, Z);

  Lock.unlock();

  F3.wait();
  ASSERT_EQ(1, X);
  ASSERT_EQ(1, Y);
  ASSERT_EQ(1, Z);
}

TEST_F(TaskQueueTest, FutureWithReturnValue) {
  ThreadPool TP(1);
  TaskQueue TQ(TP);
  std::future<std::string> F1 = TQ.async([&] { return std::string("Hello"); });
  std::future<int> F2 = TQ.async([&] { return 42; });

  ASSERT_EQ(42, F2.get());
  ASSERT_EQ("Hello", F1.get());
}
#endif
