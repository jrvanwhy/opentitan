// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

class uart_logger extends uvm_component;
  `uvm_component_utils(uart_logger)

  int logs_output_fd = 0;

  uart_agent_cfg cfg;
  uvm_tlm_analysis_fifo #(uart_item)  log_item_fifo;
  uvm_analysis_port #(string)         log_analysis_port;

  `uvm_component_new

  virtual function void build_phase(uvm_phase phase);
    log_item_fifo = new("log_item_fifo", this);
    log_analysis_port = new("log_analysis_port", this);
  endfunction

  virtual task run_phase(uvm_phase phase);
    string fname = {`gfn, ".log"};
    if (cfg.write_logs_to_file) begin
      logs_output_fd = $fopen(fname, "w");
      `DV_CHECK_FATAL((logs_output_fd !=0), $sformatf("Failed to open %s for writing", fname))
    end
    capture_logs();
  endtask

  virtual function void final_phase(uvm_phase phase);
    if (logs_output_fd != 0) $fclose(logs_output_fd);
  endfunction

  // Captures bytes received from UART TX port and constructs the logs for printing.
  virtual task capture_logs();
    uart_item item;
    string    char;
    string    log;
    byte      lf = 8'ha;   // \n
    byte      cr = 8'hd;   // \r

    fork
      forever begin
        log_item_fifo.get(item);
        char = string'(item.data);
        `uvm_info(`gfn, $sformatf("received char: %0s", char), UVM_DEBUG)
        // Continue concatenating chars into the log string untl lf or cr is encountered.
        if (item.data inside {lf, cr}) begin
          print_log(log);
          log_analysis_port.write(log);
          log = "";
        end
        else begin
          log = {log, char};
        end
      end
      forever begin
        // reset thread - if reset occurs, reset the log to an empty string.
        @(cfg.under_reset);
        if (cfg.under_reset) log = "";
      end
    join
  endtask

  // Print log with the right severity. Severity is extracted from the log string.
  // See sw/device/lib/runtime/log.h for details on how the severity is indicated.
  // TODO: Add support for verbosity when the severity is info.
  virtual function void print_log(string log);
    string info   = "INFO: *";
    string warn   = "WARNING: *";
    string error  = "ERROR: *";
    string fatal  = "FATAL: *";

    if (log == "") return;
    case (1)
      (!uvm_re_match(info, log)): begin
        `uvm_info(`gfn, log.substr(info.len() - 1, log.len() - 1), UVM_LOW)
      end
      (!uvm_re_match(warn, log)): begin
        // verilog_lint: waive forbidden-macro
        `uvm_warning(`gfn, log.substr(warn.len() - 1, log.len() - 1))
      end
      (!uvm_re_match(error, log)): begin
        `uvm_error(`gfn, log.substr(error.len() - 1, log.len() - 1))
      end
      (!uvm_re_match(fatal, log)): begin
        `uvm_fatal(`gfn, log.substr(fatal.len() - 1, log.len() - 1))
      end
      default: begin
        `uvm_info(`gfn, log, UVM_LOW)
      end
    endcase
    if (logs_output_fd != 0) begin
      $fwrite(logs_output_fd, "[%15t]: %0s\n", $time, log);
    end
  endfunction

endclass
