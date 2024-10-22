function merge(left, right, comparison) {
  const result = [];
  while ((left.length > 0) && (right.length > 0)) {
    if (comparison(left[0], right[0]) <= 0) {
      result.push(left.shift());
    } else {
      result.push(right.shift());
    }
  }
  while (left.length > 0) {
    result.push(left.shift());
  }
  while (right.length > 0) {
    result.push(right.shift());
  }
  return result;
};

/**
 * 归并排序：一种有效的排序算法，采用分治法（Divide and Conquer）策略。它将数组分为两半，递归地排序每一半，然后合并已排序的两部分
 * @param array
 * @param comparison 比较函数
 * @returns {*}
 */
export function merge_sort(array, comparison) {
  if (array.length < 2) {
    return array;
  }
  // 计算数组中间的索引。Math.ceil 确保对于奇数长度的数组，左半部分会多一个元素
  const middle = Math.ceil(array.length / 2);
  return merge(merge_sort(array.slice(0, middle), comparison), merge_sort(array.slice(middle), comparison), comparison);
};
