package com.netdisk.app.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.AutoCompleteTextView
import android.widget.Button
import android.widget.Filter
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.netdisk.app.R
import com.netdisk.app.storage.PreferencesManager

/**
 * A preset server URL paired with a short Chinese description
 * (e.g. whether that address requires logging in).
 * toString() returns just the URL so selecting it fills the input field correctly.
 */
private data class PresetUrl(val url: String, val label: String) {
    override fun toString(): String = url
}

class SettingsActivity : AppCompatActivity() {

    private lateinit var preferencesManager: PreferencesManager
    private lateinit var serverUrlInput: AutoCompleteTextView
    private lateinit var saveButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        // Enable back button in action bar
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        preferencesManager = PreferencesManager(this)

        // Initialize views
        serverUrlInput = findViewById(R.id.serverUrlInput)
        saveButton = findViewById(R.id.saveButton)

        // Dropdown with preset server address(es).
        // A plain ArrayAdapter filters options by the text already in the field
        // (e.g. a previously saved URL), so only a matching preset would show up.
        // Override the filter to always show every preset regardless of current text.
        val presetUrls = arrayOf(
            PresetUrl(getString(R.string.preset_server_url), getString(R.string.preset_server_url_label)),
            PresetUrl(getString(R.string.preset_server_url_2), getString(R.string.preset_server_url_2_label))
        )
        val presetAdapter = object : ArrayAdapter<PresetUrl>(this, R.layout.item_preset_url, presetUrls) {
            override fun getFilter(): Filter {
                return object : Filter() {
                    override fun performFiltering(constraint: CharSequence?): FilterResults {
                        return FilterResults().apply {
                            values = presetUrls
                            count = presetUrls.size
                        }
                    }

                    override fun publishResults(constraint: CharSequence?, results: FilterResults?) {
                        notifyDataSetChanged()
                    }
                }
            }

            override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
                val view = convertView ?: LayoutInflater.from(context)
                    .inflate(R.layout.item_preset_url, parent, false)
                val item = getItem(position)
                view.findViewById<TextView>(R.id.presetUrlText).text = item?.url
                view.findViewById<TextView>(R.id.presetUrlLabel).text = item?.label
                return view
            }
        }
        serverUrlInput.setAdapter(presetAdapter)

        // Load current settings
        loadSettings()

        // Save button click listener
        saveButton.setOnClickListener {
            saveSettings()
        }
    }

    private fun loadSettings() {
        // 获取各个URL值用于调试
        val lastSuccessfulUrl = preferencesManager.getLastSuccessfulUrl()
        val serverUrl = preferencesManager.getServerUrl()

        android.util.Log.d("SettingsActivity", "=== loadSettings ===")
        android.util.Log.d("SettingsActivity", "lastSuccessfulUrl: $lastSuccessfulUrl")
        android.util.Log.d("SettingsActivity", "getServerUrl(): $serverUrl")

        // 首次启动、尚未配置过服务器时，输入框保持为空
        if (!preferencesManager.hasConfigured() && lastSuccessfulUrl.isNullOrEmpty()) {
            return
        }

        // 如果是完整URL（包含http://或https://），直接显示
        if (serverUrl.startsWith("http://") || serverUrl.startsWith("https://")) {
            serverUrlInput.setText(serverUrl)
        } else {
            // 传统模式：显示主机:端口
            serverUrlInput.setText("${preferencesManager.getServerHost()}:${preferencesManager.getServerPort()}")
        }
    }

    private fun saveSettings() {
        val input = serverUrlInput.text.toString().trim()

        if (input.isEmpty()) {
            Toast.makeText(this, "服务器地址不能为空", Toast.LENGTH_SHORT).show()
            return
        }

        // 检测是否为完整URL（包含http://或https://）
        if (input.startsWith("http://") || input.startsWith("https://")) {
            // 完整URL模式（支持cloudflare tunnel等）
            var fullUrl = input

            // 移除末尾的斜杠
            if (fullUrl.endsWith("/")) {
                fullUrl = fullUrl.substring(0, fullUrl.length - 1)
            }

            // 清除旧的成功URL，让新配置生效
            preferencesManager.clearLastSuccessfulUrl()

            // 保存完整URL
            preferencesManager.saveFullServerUrl(fullUrl)
            Toast.makeText(this, "已保存完整URL: $fullUrl", Toast.LENGTH_SHORT).show()
        } else {
            // 传统的"主机:端口"模式，从同一个输入框中拆分主机和端口
            val colonIndex = input.lastIndexOf(':')
            if (colonIndex <= 0 || colonIndex == input.length - 1) {
                Toast.makeText(this, "请输入 主机:端口 或完整URL，例如 192.168.1.100:5003", Toast.LENGTH_LONG).show()
                return
            }

            val host = extractHost(input.substring(0, colonIndex))
            val portStr = input.substring(colonIndex + 1)

            val port = portStr.toIntOrNull()
            if (port == null || port < 1 || port > 65535) {
                Toast.makeText(this, "端口号无效", Toast.LENGTH_SHORT).show()
                return
            }

            // Validate URL format (basic validation)
            if (!isValidHost(host)) {
                Toast.makeText(this, getString(R.string.invalid_url), Toast.LENGTH_SHORT).show()
                return
            }

            // 清除旧的成功URL，让新配置生效
            preferencesManager.clearLastSuccessfulUrl()

            // Save settings
            preferencesManager.saveServerConfig(host, port)
            Toast.makeText(this, getString(R.string.server_config_saved), Toast.LENGTH_SHORT).show()
        }

        // Set result and go back to main activity
        setResult(RESULT_OK)
        finish()
    }

    private fun extractHost(input: String): String {
        var host = input
        // 移除 http:// 或 https:// 前缀
        if (host.startsWith("http://")) {
            host = host.substring(7)
        } else if (host.startsWith("https://")) {
            host = host.substring(8)
        }
        // 移除路径部分
        val slashIndex = host.indexOf('/')
        if (slashIndex > 0) {
            host = host.substring(0, slashIndex)
        }
        return host
    }

    private fun isValidHost(host: String): Boolean {
        // Simple validation - check if it's an IP address or domain name
        val ipPattern = Regex("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
        val domainPattern = Regex("^([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$")

        return host == "localhost" || ipPattern.matches(host) || domainPattern.matches(host)
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }
}
