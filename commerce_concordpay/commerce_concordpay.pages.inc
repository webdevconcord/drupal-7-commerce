<?php

/**
 * @file
 * Page callbacks for ConcordPay.
 */

/**
 * Callback function.
 */
function commerce_concordpay_callback() {
  $data = json_decode(file_get_contents("php://input"), TRUE);
  if (empty($data)) {
    drupal_goto('<front>');
  }
  $concordpay = new Concordpay();
  list($orderId,) = explode(Concordpay::ORDER_SEPARATOR, $data['orderReference']);

  $paymentInfo = $concordpay->isPaymentValid($data);
  $order = commerce_order_load($orderId);
  if (!$order) {
    watchdog('commerce_concordpay', 'Wrong order ID - %order_id.', ['%order_id' => $orderId], WATCHDOG_ERROR);
    exit();
  }

  if ($paymentInfo === TRUE) {
    $order_wrapper                = entity_metadata_wrapper('commerce_order', $order);
    $order->payment_remote_id     = $data['transactionId'] ?? '';
    $order->payment_remote_status = $data['transactionStatus'] ?? '';
    if ($data['type'] === Concordpay::RESPONSE_TYPE_PAYMENT) {
      // Ordinary payment.
      commerce_concordpay_create_transaction($order, $order_wrapper);
      commerce_order_status_update($order, 'processing', FALSE, NULL, 'change status');
      watchdog('commerce_concordpay', 'Order #@order paid successfully.', ['@order' => $orderId], WATCHDOG_INFO);
    }
    elseif ($data['type'] === Concordpay::RESPONSE_TYPE_REVERSE) {
      // Refunded payment.
      commerce_order_status_update($order, 'canceled', FALSE, NULL, 'change status');
      watchdog('commerce_concordpay', 'Payment for order #@order refund successfully.', ['@order' => $orderId], WATCHDOG_INFO);
    }
  }
}

/**
 * Payer will be redirected to this page after success payment.
 */
function commerce_concordpay_success() {
  $build = [];
  if (isset($_GET['order_id'], $_GET['redirect_key'])) {
    $message_alert = t('Thank you, payment approved. Order #@shop_order.', ['@shop_order' => htmlspecialchars($_GET['order_id'])]);
    drupal_set_message($message_alert, 'status');
    $build['message_success']['#markup'] = t('Payment processed successfully.') . '<br>';
    $build['message_info']['#markup'] = t('You can find a list of your orders in your personal account.');
  }
  else {
    $build = MENU_ACCESS_DENIED;
  }
  return $build;
}

/**
 * Payer will be redirected to this page after unsuccessful payment.
 */
function commerce_concordpay_fail() {
  $build = [];
  if (isset($_GET['order_id'], $_GET['redirect_key'])) {
    $message_alert = t('Unfortunately payment declined. Order #@shop_order.', ['@shop_order' => htmlspecialchars($_GET['order_id'])]);
    drupal_set_message($message_alert, 'error');
    $build['message_fail']['#markup'] = t('Payment processed fail.') . '<br>';
    $build['message_info']['#markup'] = t('You can find a list of your orders in your personal account.');
  }
  else {
    $build = MENU_ACCESS_DENIED;
  }
  return $build;
}

/**
 * The buyer will be redirected to this page if the payment is canceled.
 */
function commerce_concordpay_cancel() {
  $build = [];
  if (isset($_GET['order_id'], $_GET['redirect_key'])) {
    $message_alert = t('Canceled payment. Order #@shop_order.', ['@shop_order' => htmlspecialchars($_GET['order_id'])]);
    drupal_set_message($message_alert, 'warning');
    $build['message_cancel']['#markup'] = t('Cancellation of payment at the request of the buyer.') . '<br>';
    $build['message_info']['#markup'] = t('You can find a list of your orders in your personal account.');
  }
  else {
    $build = MENU_ACCESS_DENIED;
  }
  return $build;
}
