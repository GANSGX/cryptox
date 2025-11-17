import { useState } from 'react'
import { apiService } from '@/services/api.service'
import type { DeviceApprovalRequiredEvent } from '@/types/api.types'
import './DeviceApprovalModal.css'

interface DeviceApprovalModalProps {
  event: DeviceApprovalRequiredEvent
  onClose: () => void
}

export function DeviceApprovalModal({ event, onClose }: DeviceApprovalModalProps) {
  const [isApproving, setIsApproving] = useState(false)
  const [approvalCode, setApprovalCode] = useState<string | null>(null)

  const handleApprove = async () => {
    setIsApproving(true)

    try {
      const response = await apiService.approveDevice({
        pending_session_id: event.pending_session_id,
      })

      if (response.success && response.data) {
        setApprovalCode(response.data.approval_code)
      }
    } catch (error) {
      console.error('Failed to approve device:', error)
    } finally {
      setIsApproving(false)
    }
  }

  const handleReject = async () => {
    setIsApproving(true)

    try {
      await apiService.rejectDevice({
        pending_session_id: event.pending_session_id,
      })
      onClose()
    } catch (error) {
      console.error('Failed to reject device:', error)
    } finally {
      setIsApproving(false)
    }
  }

  return (
    <div className="device-approval-modal-overlay" onClick={onClose}>
      <div className="device-approval-modal" onClick={(e) => e.stopPropagation()}>
        {!approvalCode ? (
          // Экран подтверждения
          <>
            <div className="modal-header">
              <h2>🔔 New Login Attempt</h2>
            </div>

            <div className="modal-body">
              <div className="device-info">
                <div className="info-item">
                  <span className="info-label">Device:</span>
                  <span className="info-value">
                    {event.device_info.os}, {event.device_info.name}
                  </span>
                </div>
                <div className="info-item">
                  <span className="info-label">IP Address:</span>
                  <span className="info-value">{event.ip_address}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Time:</span>
                  <span className="info-value">
                    {new Date(event.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              </div>

              <div className="warning-box">
                <p>⚠️ Is this you trying to log in?</p>
              </div>
            </div>

            <div className="modal-footer">
              <button
                className="btn btn-secondary"
                onClick={handleReject}
                disabled={isApproving}
              >
                ❌ Reject
              </button>
              <button
                className="btn btn-primary"
                onClick={handleApprove}
                disabled={isApproving}
              >
                {isApproving ? 'Approving...' : '✅ Approve'}
              </button>
            </div>
          </>
        ) : (
          // Экран с кодом
          <>
            <div className="modal-header">
              <h2>🔑 Approval Code</h2>
            </div>

            <div className="modal-body">
              <p className="code-instruction">Show this code to your new device:</p>

              <div className="approval-code">
                {approvalCode.split('').map((digit, index) => (
                  <span key={index} className="code-digit">
                    {digit}
                  </span>
                ))}
              </div>

              <p className="code-timer">Code expires in 5 minutes</p>
            </div>

            <div className="modal-footer">
              <button className="btn btn-primary" onClick={onClose}>
                Done
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
