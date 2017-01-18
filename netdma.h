#ifndef NETDMA__H
#define NETDMA__H

#define NETDMA_CSR_SIZE 32

struct netdma_csr {
        u32 control;
        u32 status;
        u32 tx_status;
        u32 rx_report;
        u32 tx_desc_buf;
        u32 rx_desc_buf;
} __attribute__ ((packed, aligned(NETDMA_CSR_SIZE)));


struct netdma_rx_report{
  u16 actual_bytes_transferred;
  u8 sequence_number;   
  u8 flags;
};

struct netdma_tx_stat {
  u8 howmanydone;
  u8 sequence_number;
  u8 flags;
};
  

// Control
#define CTRL_RESET                                  BIT(0)

#define CTRL_RX_IRQ_ENABLE                          BIT(1) 
#define CTRL_TX_IRQ_ENABLE                          BIT(2) 

#define CTRL_CLEAR_RX_IRQ_STATUS                    BIT(3) 
#define CTRL_CLEAR_TX_IRQ_STATUS                    BIT(4) 


// Status
#define STAT_TX_IS_ANY_DONE                         BIT(0)

#define STAT_RX_REPORT_BUFFER_EMPTY                 BIT(1)

#define STAT_RX_IRQ_PENDING                         BIT(2)
#define STAT_TX_IRQ_PENDING                         BIT(3)

#define STAT_RX_DESC_BUFFER_FULL                    BIT(4) 
#define STAT_TX_DESC_BUFFER_FULL                    BIT(5)


// TX status
#define TXSTAT_DONE_CNT_OFFSET                      (0)
#define TXSTAT_DONE_CNT_MASK                        (0xFF)

#define TXSTAT_LAST_SEQ_NUM_OFFSET                  (8)
#define TXSTAT_LAST_SEQ_NUM_MASK                    (0xFF)


// RX report
#define RX_REPORT_ACTUAL_BYTES_OFFSET               (0)
#define RX_REPORT_ACTUAL_BYTES_MASK                 (0x3FFF)


// Descriptor 
#define DESC_BYTECOUNT_OFFSET                       (0) 
#define DESC_BYTECOUNT_MASK                         (0x3FFF) 

#define DESC_DISABLE_IRQ_OFFSET                     (14) 
#define DESC_DISABLE_IRQ_MASK                       (0x1) 

#define DESC_SEQ_NUM_OFFSET                         (16) 
#define DESC_SEQ_NUM_MASK                           (0xFF) 

#define TX_TIMESTAMP_OFFSET                         (24) 
#define TX_TIMESTAMP_MASK                           (0x1) 

#endif 
