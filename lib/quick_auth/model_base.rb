module QuickAuth

  module ModelBase

    def report_event(ev, opts={})
      self.handle_event_internally(ev, opts)
      self.handle_event(ev, opts)
    rescue => ex
      if defined?(Rails)
        Rails.logger.info(ex.message)
        Rails.logger.info(ex.backtrace.join("\n\t"))
      end
    end

    def handle_event_internally(ev, opts)
    end

    def handle_event(ev, opts)
      # override this in class
    end

  end

end
